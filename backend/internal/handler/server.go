package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"wallfacer-forwarder/internal/auth"
	"wallfacer-forwarder/internal/config"
	"wallfacer-forwarder/internal/database"
	"wallfacer-forwarder/internal/dns"
	"wallfacer-forwarder/internal/iptables"
	"wallfacer-forwarder/internal/model"
)

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]string{"detail": detail})
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func requireAuth(next func(w http.ResponseWriter, r *http.Request, user *model.User)) http.HandlerFunc {
	return withCORS(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "未登录或登录凭证缺失，请先登录")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		username, err := auth.VerifyAccessToken(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}
		user, err := database.DB.GetUserByUsername(username)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "用户不存在")
			return
		}
		next(w, r, user)
	})
}

func enrichRule(r *model.ForwardRule) *model.ForwardRule {
	if r.SnatIP == nil || *r.SnatIP == "" {
		resIP := ""
		if r.ResolvedIP != nil {
			resIP = *r.ResolvedIP
		}
		snat := iptables.GetLocalSnatIP(resIP)
		r.SnatIP = &snat
	}
	r.TotalBytes = r.UpBytes + r.DownBytes
	if r.Enabled {
		uSp, dSp := iptables.Mgr.GetRuleSpeed(r.ID)
		r.UpSpeed = uSp
		r.DownSpeed = dSp
	} else {
		r.UpSpeed = 0
		r.DownSpeed = 0
	}
	return r
}

func checkPortConflict(listenPort int, protocol string, excludeID int) error {
	rules, err := database.DB.ListRules()
	if err != nil {
		return err
	}
	reqTCP := protocol == "tcp" || protocol == "tcp+udp"
	reqUDP := protocol == "udp" || protocol == "tcp+udp"

	for _, r := range rules {
		if r.ID == excludeID || r.ListenPort != listenPort {
			continue
		}
		rTCP := r.Protocol == "tcp" || r.Protocol == "tcp+udp"
		rUDP := r.Protocol == "udp" || r.Protocol == "tcp+udp"
		if (reqTCP && rTCP) || (reqUDP && rUDP) {
			return fmt.Errorf("本机监听端口 %d (%s) 与已有规则 [%s] 冲突", listenPort, protocol, r.Name)
		}
	}
	return nil
}

func NewRouter(frontendDir string) http.Handler {
	mux := http.NewServeMux()

	// 1. 等保三级挑战码接口
	mux.HandleFunc("/api/auth/challenge", withCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		writeJSON(w, http.StatusOK, auth.IssueChallenge())
	}))

	// 2. 等保三级登录接口 (账号+密码整体 RSA-2048 密文传输)
	mux.HandleFunc("/api/auth/login", withCORS(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		var req model.LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "请求参数格式错误")
			return
		}
		if err := auth.ConsumeChallenge(req.Nonce); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		username, plainPassword, err := auth.DecryptLoginCredentials(req.EncryptedCredentials, req.Nonce)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		user, err := database.DB.GetUserByUsername(username)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "用户名或密码错误")
			return
		}

		now := time.Now()
		if user.LockedUntil != nil && user.LockedUntil.After(now) {
			remainMin := int(user.LockedUntil.Sub(now).Minutes()) + 1
			writeError(w, http.StatusLocked, fmt.Sprintf("由于连续登录失败次数过多，账号已锁定，请 %d 分钟后再试", remainMin))
			return
		}

		maxAttempts := config.Global.Auth.MaxFailedAttempts
		lockMinutes := config.Global.Auth.LockoutMinutes
		if !auth.VerifyPassword(plainPassword, user.PasswordHash) {
			user.FailedAttempts++
			if user.FailedAttempts >= maxAttempts {
				lockUntil := now.Add(time.Duration(lockMinutes) * time.Minute)
				user.LockedUntil = &lockUntil
				user.FailedAttempts = 0
				_ = database.DB.UpdateUser(user)
				writeError(w, http.StatusLocked, fmt.Sprintf("连续登录失败达 %d 次，已触发等保三级保护锁定 %d 分钟", maxAttempts, lockMinutes))
				return
			}
			remain := maxAttempts - user.FailedAttempts
			_ = database.DB.UpdateUser(user)
			writeError(w, http.StatusUnauthorized, fmt.Sprintf("用户名或密码错误（还剩 %d 次尝试机会，连续失败 %d 次将锁定 %d 分钟）", remain, maxAttempts, lockMinutes))
			return
		}

		user.FailedAttempts = 0
		user.LockedUntil = nil
		user.LastLoginAt = &now
		_ = database.DB.UpdateUser(user)

		token, _ := auth.CreateAccessToken(user.Username)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"access_token":            token,
			"token_type":              "bearer",
			"username":                user.Username,
			"session_timeout_minutes": config.Global.Auth.SessionTimeoutMinutes,
			"last_login_at":           user.LastLoginAt,
			"password_changed_at":     user.PasswordChangedAt,
		})
	}))

	// 3. 当前用户信息
	mux.HandleFunc("/api/auth/me", requireAuth(func(w http.ResponseWriter, r *http.Request, user *model.User) {
		writeJSON(w, http.StatusOK, user)
	}))

	// 4. 修改密码（等保三级强口令校验）
	mux.HandleFunc("/api/auth/password", requireAuth(func(w http.ResponseWriter, r *http.Request, user *model.User) {
		if r.Method != http.MethodPut {
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		var req model.PasswordChangeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "请求参数无效")
			return
		}
		if err := auth.ConsumeChallenge(req.Nonce); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		oldPwd, err := auth.DecryptPasswordCipher(req.EncryptedOldPassword, req.Nonce)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		newPwd, err := auth.DecryptPasswordCipher(req.EncryptedNewPassword, req.Nonce)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !auth.VerifyPassword(oldPwd, user.PasswordHash) {
			writeError(w, http.StatusBadRequest, "原密码不正确")
			return
		}
		if oldPwd == newPwd {
			writeError(w, http.StatusBadRequest, "新密码不能与原密码相同（等保三级要求）")
			return
		}
		if err := auth.ValidateGrade3Password(newPwd, user.Username); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		user.PasswordHash = auth.HashPassword(newPwd, "")
		user.PasswordChangedAt = time.Now()
		_ = database.DB.UpdateUser(user)
		writeJSON(w, http.StatusOK, map[string]string{"message": "密码修改成功（已满足等保三级口令策略）"})
	}))

	// 5. 测试数据库连接状态接口（数据库配置在 config.yaml 中 DIY，前端不展示库名及连接信息）
	mux.HandleFunc("/api/db/test", requireAuth(func(w http.ResponseWriter, r *http.Request, user *model.User) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		connected, latencyMs, msg := database.DB.TestConnection()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"connected":  connected,
			"latency_ms": latencyMs,
			"message":    msg,
		})
	}))

	// 6. 系统状态接口
	mux.HandleFunc("/api/status", requireAuth(func(w http.ResponseWriter, r *http.Request, user *model.User) {
		rules, _ := database.DB.ListRules()
		totalRules := len(rules)
		enabledRules := 0
		domainRules := 0
		var activeList []*model.ForwardRule
		var totalUpBytes, totalDownBytes int64
		var totalUpSpeed, totalDownSpeed float64

		for _, rule := range rules {
			totalUpBytes += rule.UpBytes
			totalDownBytes += rule.DownBytes
			if rule.IsDomain {
				domainRules++
			}
			if rule.Enabled {
				enabledRules++
				activeList = append(activeList, rule)
				uSp, dSp := iptables.Mgr.GetRuleSpeed(rule.ID)
				totalUpSpeed += uSp
				totalDownSpeed += dSp
			}
		}

		iptStatus := iptables.Mgr.GetStatus(activeList)
		if len(activeList) == 0 || iptables.Mgr.HostUpSpeed > 0 || iptables.Mgr.HostDownSpeed > 0 {
			if totalUpSpeed == 0 && totalDownSpeed == 0 {
				totalUpSpeed = iptables.Mgr.HostUpSpeed
				totalDownSpeed = iptables.Mgr.HostDownSpeed
			}
			if totalUpBytes == 0 && totalDownBytes == 0 {
				totalUpBytes = iptables.Mgr.HostUpBytes
				totalDownBytes = iptables.Mgr.HostDownBytes
			}
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"total_rules":   totalRules,
			"enabled_rules": enabledRules,
			"domain_rules":  domainRules,
			"db_connected":  database.DB.IsMySQLConnected(),
			"traffic": map[string]interface{}{
				"total_up_bytes":   totalUpBytes,
				"total_down_bytes": totalDownBytes,
				"total_bytes":      totalUpBytes + totalDownBytes,
				"total_up_speed":   totalUpSpeed,
				"total_down_speed": totalDownSpeed,
			},
			"dns_watcher": map[string]interface{}{
				"is_running":       dns.GlobalWatcher.IsRunning,
				"interval_seconds": dns.GlobalWatcher.IntervalSeconds,
				"last_run_at":      dns.GlobalWatcher.LastRunAt,
			},
			"iptables": iptStatus,
		})
	}))

	// 7. DNS 监控接口
	mux.HandleFunc("/api/dns/interval", requireAuth(func(w http.ResponseWriter, r *http.Request, user *model.User) {
		if r.Method != http.MethodPut {
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		var req model.DnsIntervalRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IntervalSeconds < 5 {
			writeError(w, http.StatusBadRequest, "检测间隔不能小于 5 秒")
			return
		}
		dns.GlobalWatcher.SetInterval(req.IntervalSeconds)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message":          fmt.Sprintf("域名检测周期已更新为 %d 秒", req.IntervalSeconds),
			"interval_seconds": req.IntervalSeconds,
		})
	}))

	mux.HandleFunc("/api/dns/check-now", requireAuth(func(w http.ResponseWriter, r *http.Request, user *model.User) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		res := dns.GlobalWatcher.CheckAllDomains()
		writeJSON(w, http.StatusOK, res)
	}))

	mux.HandleFunc("/api/dns/logs", requireAuth(func(w http.ResponseWriter, r *http.Request, user *model.User) {
		logs, _ := database.DB.ListDnsLogs(50)
		if logs == nil {
			logs = []*model.DnsChangeLog{}
		}
		writeJSON(w, http.StatusOK, logs)
	}))

	// 8. 规则同步与列表/新增
	mux.HandleFunc("/api/rules/sync", requireAuth(func(w http.ResponseWriter, r *http.Request, user *model.User) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		rules, _ := database.DB.ListRules()
		executed, _ := iptables.Mgr.SyncAllRules(rules)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message":                 fmt.Sprintf("成功同步规则到转发引擎 (共执行 %d 条指令)", len(executed)),
			"executed_commands_count": len(executed),
		})
	}))

	mux.HandleFunc("/api/rules", requireAuth(func(w http.ResponseWriter, r *http.Request, user *model.User) {
		if r.Method == http.MethodGet {
			rules, _ := database.DB.ListRules()
			out := make([]*model.ForwardRule, 0, len(rules))
			for _, rule := range rules {
				out = append(out, enrichRule(rule))
			}
			writeJSON(w, http.StatusOK, out)
			return
		}
		if r.Method == http.MethodPost {
			var req model.RuleMutationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, "参数错误")
				return
			}
			proto := strings.ToLower(strings.TrimSpace(req.Protocol))
			if proto != "tcp" && proto != "udp" && proto != "tcp+udp" {
				writeError(w, http.StatusBadRequest, "协议仅支持 tcp, udp 或 tcp+udp")
				return
			}
			if err := checkPortConflict(req.ListenPort, proto, 0); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}

			targetHost := strings.TrimSpace(req.TargetHost)
			isDomain := !iptables.IsIPv4Address(targetHost)
			now := time.Now()
			var resolvedIP *string
			var lastErr *string
			var lastChecked, lastChanged *time.Time

			if ip, err := iptables.ResolveHostIPv4(targetHost); err == nil {
				resolvedIP = &ip
				lastChanged = &now
			} else {
				eStr := err.Error()
				lastErr = &eStr
			}
			if isDomain {
				lastChecked = &now
			}

			resIPStr := ""
			if resolvedIP != nil {
				resIPStr = *resolvedIP
			}
			snatVal := iptables.GetLocalSnatIP(resIPStr)
			if req.SnatIP != nil && iptables.IsIPv4Address(*req.SnatIP) {
				snatVal = strings.TrimSpace(*req.SnatIP)
			}

			rule := &model.ForwardRule{
				Name:          strings.TrimSpace(req.Name),
				Protocol:      proto,
				ListenPort:    req.ListenPort,
				TargetHost:    targetHost,
				TargetPort:    req.TargetPort,
				IsDomain:      isDomain,
				ResolvedIP:    resolvedIP,
				SnatIP:        &snatVal,
				Enabled:       req.Enabled,
				LastCheckedAt: lastChecked,
				LastChangedAt: lastChanged,
				LastError:     lastErr,
			}
			created, err := database.DB.CreateRule(rule)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if isDomain && resolvedIP != nil {
				_ = database.DB.AddDnsLog(&model.DnsChangeLog{
					RuleID:    created.ID,
					RuleName:  created.Name,
					Domain:    created.TargetHost,
					OldIP:     nil,
					NewIP:     *resolvedIP,
					CreatedAt: now,
				})
			}
			allRules, _ := database.DB.ListRules()
			_, _ = iptables.Mgr.SyncAllRules(allRules)
			writeJSON(w, http.StatusOK, enrichRule(created))
			return
		}
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}))

	// 9. 单条规则操作: /api/rules/{id}, /api/rules/{id}/toggle, /api/rules/{id}/reset-traffic
	mux.HandleFunc("/api/rules/", requireAuth(func(w http.ResponseWriter, r *http.Request, user *model.User) {
		trimmed := strings.TrimPrefix(r.URL.Path, "/api/rules/")
		parts := strings.Split(strings.Trim(trimmed, "/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			writeError(w, http.StatusNotFound, "Not found")
			return
		}
		ruleID, err := strconv.Atoi(parts[0])
		if err != nil {
			writeError(w, http.StatusBadRequest, "规则 ID 无效")
			return
		}

		rule, err := database.DB.GetRule(ruleID)
		if err != nil {
			writeError(w, http.StatusNotFound, "规则不存在")
			return
		}

		// /api/rules/{id}/toggle
		if len(parts) == 2 && parts[1] == "toggle" && r.Method == http.MethodPost {
			rule.Enabled = !rule.Enabled
			if rule.Enabled && (rule.ResolvedIP == nil || *rule.ResolvedIP == "") {
				if ip, err := iptables.ResolveHostIPv4(rule.TargetHost); err == nil {
					rule.ResolvedIP = &ip
					rule.LastError = nil
				}
			}
			_ = database.DB.UpdateRule(rule)
			allRules, _ := database.DB.ListRules()
			_, _ = iptables.Mgr.SyncAllRules(allRules)
			writeJSON(w, http.StatusOK, enrichRule(rule))
			return
		}

		// /api/rules/{id}/reset-traffic
		if len(parts) == 2 && parts[1] == "reset-traffic" && r.Method == http.MethodPost {
			rule.UpBytes = 0
			rule.DownBytes = 0
			_ = database.DB.UpdateRule(rule)
			writeJSON(w, http.StatusOK, enrichRule(rule))
			return
		}

		// /api/rules/{id}/resolve (单条规则刷新域名解析并用解析出的 IP 覆盖配置)
		if len(parts) == 2 && parts[1] == "resolve" && r.Method == http.MethodPost {
			now := time.Now()
			oldIP := ""
			if rule.ResolvedIP != nil {
				oldIP = *rule.ResolvedIP
			}
			newIP, err := iptables.ResolveHostIPv4(rule.TargetHost)
			rule.LastCheckedAt = &now
			if err != nil {
				errStr := err.Error()
				rule.LastError = &errStr
				_ = database.DB.UpdateRule(rule)
				writeError(w, http.StatusBadRequest, errStr)
				return
			}
			rule.LastError = nil
			rule.ResolvedIP = &newIP
			if oldIP != newIP {
				rule.LastChangedAt = &now
				if rule.IsDomain {
					var oldPtr *string
					if oldIP != "" {
						oldPtr = &oldIP
					}
					_ = database.DB.AddDnsLog(&model.DnsChangeLog{
						RuleID:    rule.ID,
						RuleName:  rule.Name,
						Domain:    rule.TargetHost,
						OldIP:     oldPtr,
						NewIP:     newIP,
						CreatedAt: now,
					})
				}
			}
			_ = database.DB.UpdateRule(rule)
			allRules, _ := database.DB.ListRules()
			_, _ = iptables.Mgr.SyncAllRules(allRules)
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"message":     fmt.Sprintf("已刷新解析 [%s] -> %s 并覆盖生效配置", rule.TargetHost, newIP),
				"resolved_ip": newIP,
				"rule":        enrichRule(rule),
			})
			return
		}

		// PUT /api/rules/{id}
		if len(parts) == 1 && r.Method == http.MethodPut {
			var req model.RuleMutationRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeError(w, http.StatusBadRequest, "参数错误")
				return
			}
			proto := strings.ToLower(strings.TrimSpace(req.Protocol))
			if err := checkPortConflict(req.ListenPort, proto, ruleID); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			targetHost := strings.TrimSpace(req.TargetHost)
			isDomain := !iptables.IsIPv4Address(targetHost)
			now := time.Now()
			oldIP := ""
			if rule.ResolvedIP != nil {
				oldIP = *rule.ResolvedIP
			}

			var resolvedIP *string
			var lastErr *string
			if ip, err := iptables.ResolveHostIPv4(targetHost); err == nil {
				resolvedIP = &ip
			} else {
				eStr := err.Error()
				lastErr = &eStr
			}

			resIPStr := ""
			if resolvedIP != nil {
				resIPStr = *resolvedIP
			}
			snatVal := iptables.GetLocalSnatIP(resIPStr)
			if req.SnatIP != nil && iptables.IsIPv4Address(*req.SnatIP) {
				snatVal = strings.TrimSpace(*req.SnatIP)
			}

			rule.Name = strings.TrimSpace(req.Name)
			rule.Protocol = proto
			rule.ListenPort = req.ListenPort
			rule.TargetHost = targetHost
			rule.TargetPort = req.TargetPort
			rule.IsDomain = isDomain
			rule.ResolvedIP = resolvedIP
			rule.SnatIP = &snatVal
			rule.Enabled = req.Enabled
			if isDomain {
				rule.LastCheckedAt = &now
			}
			if resolvedIP != nil && *resolvedIP != oldIP {
				rule.LastChangedAt = &now
				if isDomain {
					var oldPtr *string
					if oldIP != "" {
						oldPtr = &oldIP
					}
					_ = database.DB.AddDnsLog(&model.DnsChangeLog{
						RuleID:    rule.ID,
						RuleName:  rule.Name,
						Domain:    rule.TargetHost,
						OldIP:     oldPtr,
						NewIP:     *resolvedIP,
						CreatedAt: now,
					})
				}
			}
			rule.LastError = lastErr
			_ = database.DB.UpdateRule(rule)

			allRules, _ := database.DB.ListRules()
			_, _ = iptables.Mgr.SyncAllRules(allRules)
			writeJSON(w, http.StatusOK, enrichRule(rule))
			return
		}

		// DELETE /api/rules/{id}
		if len(parts) == 1 && r.Method == http.MethodDelete {
			_ = database.DB.DeleteRule(ruleID)
			allRules, _ := database.DB.ListRules()
			_, _ = iptables.Mgr.SyncAllRules(allRules)
			writeJSON(w, http.StatusOK, map[string]string{"message": "规则已删除并从转发引擎中移除"})
			return
		}

		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}))

	// 静态文件托管（支持前后端独立部署，同时支持直接访问根路径加载 Vue 3 应用）
	if frontendDir != "" {
		fs := http.FileServer(http.Dir(frontendDir))
		mux.Handle("/", fs)
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join("..", "frontend", "index.html"))
		})
	}

	return mux
}

