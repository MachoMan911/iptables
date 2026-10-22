package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"

	"wallfacer-forwarder/internal/auth"
	"wallfacer-forwarder/internal/config"
	"wallfacer-forwarder/internal/model"
)

// buildMySQLDSN 使用官方 mysql.Config 构造 DSN，避免 url.QueryEscape 将密码中的 @、# 等特殊字符转义成 %40、%23 导致认证失败
func buildMySQLDSN(cfg config.MySQLConfig, dbName string, timeout time.Duration) string {
	mc := mysql.NewConfig()
	mc.User = cfg.User
	mc.Passwd = cfg.Password
	mc.Net = "tcp"
	mc.Addr = fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	mc.DBName = dbName
	mc.Timeout = timeout
	mc.ReadTimeout = 10 * time.Second
	mc.WriteTimeout = 10 * time.Second
	mc.ParseTime = true
	mc.Loc = time.Local
	mc.AllowNativePasswords = true
	if cfg.Charset != "" {
		mc.Params = map[string]string{"charset": cfg.Charset}
	}
	return mc.FormatDSN()
}

type Store struct {
	mu           sync.RWMutex
	db           *sql.DB
	isMySQL      bool
	activeMode   string
	fallbackPath string
	memUsers     []*model.User
	memRules     []*model.ForwardRule
	memLogs      []*model.DnsChangeLog
	nextRuleID   int
	nextLogID    int
}

var DB = &Store{
	fallbackPath: "local_store.json",
	nextRuleID:   1,
	nextLogID:    1,
}

type localPersistData struct {
	Users      []*model.User         `json:"users"`
	Rules      []*model.ForwardRule  `json:"rules"`
	Logs       []*model.DnsChangeLog `json:"logs"`
	NextRuleID int                   `json:"next_rule_id"`
	NextLogID  int                   `json:"next_log_id"`
}

func (s *Store) Init() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.initLocked()
}

func (s *Store) ReconnectWithNewConfig(newCfg config.MySQLConfig) error {
	if err := config.UpdateMySQLConfig(newCfg); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		_ = s.db.Close()
		s.db = nil
	}
	return s.initLocked()
}

func (s *Store) initLocked() error {
	cfg := config.Global.MySQL
	if err := config.ValidateDatabaseName(cfg.Database); err != nil {
		return err
	}

	// 1. 尝试连接 MySQL 实例并自动创建自定义名称的数据库
	rootDSN := buildMySQLDSN(cfg, "", 3*time.Second)
	if rootDB, err := sql.Open("mysql", rootDSN); err == nil {
		if pingErr := rootDB.Ping(); pingErr == nil {
			createSQL := fmt.Sprintf(
				"CREATE DATABASE IF NOT EXISTS `%s` DEFAULT CHARACTER SET %s COLLATE %s_unicode_ci;",
				cfg.Database, cfg.Charset, cfg.Charset,
			)
			_, _ = rootDB.Exec(createSQL)
		} else {
			log.Printf("MySQL 实例连接提示 (%s:%d): %v", cfg.Host, cfg.Port, pingErr)
		}
		_ = rootDB.Close()
	}

	// 2. 直接连接至自定义数据库并自动初始化表结构（兼容仅授权单库权限的业务账号）
	dbDSN := buildMySQLDSN(cfg, cfg.Database, 5*time.Second)
	if conn, err := sql.Open("mysql", dbDSN); err == nil {
		conn.SetMaxOpenConns(20)
		conn.SetMaxIdleConns(10)
		conn.SetConnMaxLifetime(time.Hour)
		if err := conn.Ping(); err == nil {
			s.db = conn
			s.isMySQL = true
			s.activeMode = fmt.Sprintf("MySQL (%s:%d/%s)", cfg.Host, cfg.Port, cfg.Database)
			if err := s.migrateMySQLTables(); err != nil {
				log.Printf("MySQL 表结构初始化失败: %v", err)
				return err
			}
			log.Printf("已成功连接 MySQL 自定义数据库 [%s] 并完成表结构初始化", cfg.Database)
			return nil
		} else {
			log.Printf("连接自定义数据库 [%s] 失败: %v", cfg.Database, err)
			_ = conn.Close()
		}
	}

	// 3. 若本地未启动 MySQL，回退至本地持久化存储以保证本地预览可用
	s.isMySQL = false
	s.activeMode = fmt.Sprintf("本地预览模式 (自定义库名: %s，待 MySQL %s:%d 就绪后自动接入)", cfg.Database, cfg.Host, cfg.Port)
	s.loadFallbackLocked()
	return nil
}

func (s *Store) migrateMySQLTables() error {
	tableSQLs := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			username VARCHAR(64) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			failed_attempts INT NOT NULL DEFAULT 0,
			locked_until DATETIME DEFAULT NULL,
			password_changed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_login_at DATETIME DEFAULT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

		`CREATE TABLE IF NOT EXISTS forward_rules (
			id INT AUTO_INCREMENT PRIMARY KEY,
			name VARCHAR(128) NOT NULL,
			protocol VARCHAR(16) NOT NULL DEFAULT 'tcp+udp',
			listen_port INT NOT NULL,
			target_host VARCHAR(255) NOT NULL,
			target_port INT NOT NULL,
			is_domain TINYINT(1) NOT NULL DEFAULT 0,
			resolved_ip VARCHAR(64) DEFAULT NULL,
			snat_ip VARCHAR(64) DEFAULT NULL,
			up_bytes BIGINT NOT NULL DEFAULT 0,
			down_bytes BIGINT NOT NULL DEFAULT 0,
			enabled TINYINT(1) NOT NULL DEFAULT 1,
			last_checked_at DATETIME DEFAULT NULL,
			last_changed_at DATETIME DEFAULT NULL,
			last_error VARCHAR(512) DEFAULT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			UNIQUE KEY uk_listen_port_proto (listen_port, protocol)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,

		`CREATE TABLE IF NOT EXISTS dns_change_logs (
			id INT AUTO_INCREMENT PRIMARY KEY,
			rule_id INT NOT NULL,
			rule_name VARCHAR(128) NOT NULL,
			domain VARCHAR(255) NOT NULL,
			old_ip VARCHAR(64) DEFAULT NULL,
			new_ip VARCHAR(64) NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_rule_id (rule_id),
			INDEX idx_created_at (created_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,
	}

	for _, q := range tableSQLs {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}

	var count int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err == nil && count == 0 {
		hash := auth.HashPassword(config.Global.Auth.InitialAdminPassword, "")
		_, _ = s.db.Exec(
			"INSERT INTO users (username, password_hash, failed_attempts) VALUES (?, ?, 0)",
			config.Global.Auth.InitialAdminUser, hash,
		)
	}
	// 重启程序自动清零所有账号的登录失败计数与锁定状态
	_, _ = s.db.Exec("UPDATE users SET failed_attempts = 0, locked_until = NULL")
	return nil
}

func (s *Store) loadFallbackLocked() {
	if config.Global.ConfigPath != "" {
		dir := filepath.Dir(config.Global.ConfigPath)
		if dir != "" && dir != "." {
			s.fallbackPath = filepath.Join(dir, "local_store.json")
		}
	}
	if data, err := os.ReadFile(s.fallbackPath); err == nil {
		var p localPersistData
		if json.Unmarshal(data, &p) == nil {
			s.memUsers = p.Users
			s.memRules = p.Rules
			s.memLogs = p.Logs
			if p.NextRuleID > 0 {
				s.nextRuleID = p.NextRuleID
			}
			if p.NextLogID > 0 {
				s.nextLogID = p.NextLogID
			}
		}
	}
	needSave := false
	for _, u := range s.memUsers {
		if u.PasswordHash == "" {
			u.PasswordHash = auth.HashPassword(config.Global.Auth.InitialAdminPassword, "")
			needSave = true
		}
		// 重启程序自动清零登录失败锁定状态
		if u.FailedAttempts != 0 || u.LockedUntil != nil {
			u.FailedAttempts = 0
			u.LockedUntil = nil
			needSave = true
		}
	}
	if len(s.memUsers) == 0 {
		now := time.Now()
		s.memUsers = []*model.User{
			{
				ID:                1,
				Username:          config.Global.Auth.InitialAdminUser,
				PasswordHash:      auth.HashPassword(config.Global.Auth.InitialAdminPassword, ""),
				FailedAttempts:    0,
				PasswordChangedAt: now,
				CreatedAt:         now,
				UpdatedAt:         now,
			},
		}
		needSave = true
	}
	if needSave {
		s.saveFallbackLocked()
	}
}

// TestConnection 重新加载 config.yaml 并测试数据库连接是否正常（不在前端暴露数据库名称或连接串信息）
func (s *Store) TestConnection() (bool, int64, string) {
	_ = config.Load(config.Global.ConfigPath)
	cfg := config.Global.MySQL
	start := time.Now()
	if err := config.ValidateDatabaseName(cfg.Database); err != nil {
		return false, 0, "配置文件中的数据库名格式不合法"
	}

	rootDSN := buildMySQLDSN(cfg, "", 3*time.Second)
	if rootDB, err := sql.Open("mysql", rootDSN); err == nil {
		if err := rootDB.Ping(); err == nil {
			createSQL := fmt.Sprintf(
				"CREATE DATABASE IF NOT EXISTS `%s` DEFAULT CHARACTER SET %s COLLATE %s_unicode_ci;",
				cfg.Database, cfg.Charset, cfg.Charset,
			)
			_, _ = rootDB.Exec(createSQL)
		}
		_ = rootDB.Close()
	}

	dbDSN := buildMySQLDSN(cfg, cfg.Database, 5*time.Second)
	conn, err := sql.Open("mysql", dbDSN)
	if err != nil {
		return false, time.Since(start).Milliseconds(), "数据库连接失败（驱动初始化异常）"
	}
	if err := conn.Ping(); err != nil {
		_ = conn.Close()
		log.Printf("测试数据库连接未通过: %v", err)
		return false, time.Since(start).Milliseconds(), "数据库连接测试未通过：无法连接至配置文件指定的 MySQL 服务（当前使用本地存储回退）"
	}
	latency := time.Since(start).Milliseconds()

	s.mu.Lock()
	if s.db != nil {
		_ = s.db.Close()
	}
	conn.SetMaxOpenConns(20)
	conn.SetMaxIdleConns(10)
	conn.SetConnMaxLifetime(time.Hour)
	s.db = conn
	s.isMySQL = true
	s.activeMode = fmt.Sprintf("MySQL (%s:%d/%s)", cfg.Host, cfg.Port, cfg.Database)
	_ = s.migrateMySQLTables()
	s.mu.Unlock()

	return true, latency, fmt.Sprintf("数据库连接测试成功 (响应耗时 %d ms)", latency)
}

func (s *Store) saveFallbackLocked() {
	p := localPersistData{
		Users:      s.memUsers,
		Rules:      s.memRules,
		Logs:       s.memLogs,
		NextRuleID: s.nextRuleID,
		NextLogID:  s.nextLogID,
	}
	if out, err := json.MarshalIndent(p, "", "  "); err == nil {
		_ = os.WriteFile(s.fallbackPath, out, 0600)
	}
}

func (s *Store) ActiveMode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeMode
}

func (s *Store) IsMySQLConnected() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isMySQL
}

// ==================== 用户操作 ====================

func (s *Store) GetUserByUsername(username string) (*model.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.isMySQL {
		u := &model.User{}
		var lockedUntil, lastLogin sql.NullTime
		err := s.db.QueryRow(
			`SELECT id, username, password_hash, failed_attempts, locked_until, password_changed_at, last_login_at, created_at, updated_at
			 FROM users WHERE username = ? LIMIT 1`, username,
		).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.FailedAttempts, &lockedUntil, &u.PasswordChangedAt, &lastLogin, &u.CreatedAt, &u.UpdatedAt)
		if err != nil {
			return nil, err
		}
		if lockedUntil.Valid {
			u.LockedUntil = &lockedUntil.Time
		}
		if lastLogin.Valid {
			u.LastLoginAt = &lastLogin.Time
		}
		return u, nil
	}

	for _, u := range s.memUsers {
		if u.Username == username {
			cp := *u
			return &cp, nil
		}
	}
	return nil, errors.New("用户不存在")
}

func (s *Store) UpdateUser(u *model.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u.UpdatedAt = time.Now()
	if s.isMySQL {
		_, err := s.db.Exec(
			`UPDATE users SET password_hash=?, failed_attempts=?, locked_until=?, password_changed_at=?, last_login_at=?, updated_at=? WHERE id=?`,
			u.PasswordHash, u.FailedAttempts, u.LockedUntil, u.PasswordChangedAt, u.LastLoginAt, u.UpdatedAt, u.ID,
		)
		return err
	}

	for i, existing := range s.memUsers {
		if existing.ID == u.ID {
			cp := *u
			s.memUsers[i] = &cp
			s.saveFallbackLocked()
			return nil
		}
	}
	return errors.New("用户不存在")
}

// ==================== 转发规则操作 ====================

func (s *Store) ListRules() ([]*model.ForwardRule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.isMySQL {
		rows, err := s.db.Query(
			`SELECT id, name, protocol, listen_port, target_host, target_port, is_domain,
			 resolved_ip, snat_ip, up_bytes, down_bytes, enabled, last_checked_at, last_changed_at, last_error, created_at, updated_at
			 FROM forward_rules ORDER BY id DESC`,
		)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var list []*model.ForwardRule
		for rows.Next() {
			r := &model.ForwardRule{}
			var resolvedIP, snatIP, lastErr sql.NullString
			var lastChecked, lastChanged sql.NullTime
			if err := rows.Scan(
				&r.ID, &r.Name, &r.Protocol, &r.ListenPort, &r.TargetHost, &r.TargetPort, &r.IsDomain,
				&resolvedIP, &snatIP, &r.UpBytes, &r.DownBytes, &r.Enabled, &lastChecked, &lastChanged, &lastErr, &r.CreatedAt, &r.UpdatedAt,
			); err != nil {
				return nil, err
			}
			if resolvedIP.Valid {
				r.ResolvedIP = &resolvedIP.String
			}
			if snatIP.Valid {
				r.SnatIP = &snatIP.String
			}
			if lastChecked.Valid {
				r.LastCheckedAt = &lastChecked.Time
			}
			if lastChanged.Valid {
				r.LastChangedAt = &lastChanged.Time
			}
			if lastErr.Valid {
				r.LastError = &lastErr.String
			}
			r.TotalBytes = r.UpBytes + r.DownBytes
			list = append(list, r)
		}
		return list, nil
	}

	res := make([]*model.ForwardRule, 0, len(s.memRules))
	for i := len(s.memRules) - 1; i >= 0; i-- {
		cp := *s.memRules[i]
		cp.TotalBytes = cp.UpBytes + cp.DownBytes
		res = append(res, &cp)
	}
	return res, nil
}

func (s *Store) GetRule(id int) (*model.ForwardRule, error) {
	rules, err := s.ListRules()
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		if r.ID == id {
			return r, nil
		}
	}
	return nil, errors.New("规则不存在")
}

func (s *Store) CreateRule(r *model.ForwardRule) (*model.ForwardRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	r.CreatedAt = now
	r.UpdatedAt = now

	if s.isMySQL {
		res, err := s.db.Exec(
			`INSERT INTO forward_rules
			 (name, protocol, listen_port, target_host, target_port, is_domain, resolved_ip, snat_ip, up_bytes, down_bytes, enabled, last_checked_at, last_changed_at, last_error, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.Name, r.Protocol, r.ListenPort, r.TargetHost, r.TargetPort, r.IsDomain,
			r.ResolvedIP, r.SnatIP, r.UpBytes, r.DownBytes, r.Enabled, r.LastCheckedAt, r.LastChangedAt, r.LastError, r.CreatedAt, r.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		lastID, _ := res.LastInsertId()
		r.ID = int(lastID)
		return r, nil
	}

	r.ID = s.nextRuleID
	s.nextRuleID++
	cp := *r
	s.memRules = append(s.memRules, &cp)
	s.saveFallbackLocked()
	return r, nil
}

func (s *Store) UpdateRule(r *model.ForwardRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	r.UpdatedAt = time.Now()
	if s.isMySQL {
		_, err := s.db.Exec(
			`UPDATE forward_rules SET
			 name=?, protocol=?, listen_port=?, target_host=?, target_port=?, is_domain=?,
			 resolved_ip=?, snat_ip=?, up_bytes=?, down_bytes=?, enabled=?, last_checked_at=?, last_changed_at=?, last_error=?, updated_at=?
			 WHERE id=?`,
			r.Name, r.Protocol, r.ListenPort, r.TargetHost, r.TargetPort, r.IsDomain,
			r.ResolvedIP, r.SnatIP, r.UpBytes, r.DownBytes, r.Enabled, r.LastCheckedAt, r.LastChangedAt, r.LastError, r.UpdatedAt, r.ID,
		)
		return err
	}

	for i, existing := range s.memRules {
		if existing.ID == r.ID {
			cp := *r
			s.memRules[i] = &cp
			s.saveFallbackLocked()
			return nil
		}
	}
	return errors.New("规则不存在")
}

func (s *Store) DeleteRule(id int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isMySQL {
		_, err := s.db.Exec("DELETE FROM forward_rules WHERE id = ?", id)
		return err
	}

	for i, existing := range s.memRules {
		if existing.ID == id {
			s.memRules = append(s.memRules[:i], s.memRules[i+1:]...)
			s.saveFallbackLocked()
			return nil
		}
	}
	return errors.New("规则不存在")
}

func (s *Store) AddTrafficDelta(deltas map[int][2]int64) {
	if len(deltas) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.isMySQL {
		for rid, d := range deltas {
			if d[0] > 0 || d[1] > 0 {
				_, _ = s.db.Exec(
					"UPDATE forward_rules SET up_bytes = up_bytes + ?, down_bytes = down_bytes + ? WHERE id = ?",
					d[0], d[1], rid,
				)
			}
		}
		return
	}

	dirty := false
	for _, r := range s.memRules {
		if d, ok := deltas[r.ID]; ok && (d[0] > 0 || d[1] > 0) {
			r.UpBytes += d[0]
			r.DownBytes += d[1]
			dirty = true
		}
	}
	if dirty {
		s.saveFallbackLocked()
	}
}

// ==================== 域名变更日志操作 ====================

func (s *Store) AddDnsLog(entry *model.DnsChangeLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now()
	}
	if s.isMySQL {
		_, err := s.db.Exec(
			"INSERT INTO dns_change_logs (rule_id, rule_name, domain, old_ip, new_ip, created_at) VALUES (?, ?, ?, ?, ?, ?)",
			entry.RuleID, entry.RuleName, entry.Domain, entry.OldIP, entry.NewIP, entry.CreatedAt,
		)
		return err
	}

	entry.ID = s.nextLogID
	s.nextLogID++
	cp := *entry
	s.memLogs = append(s.memLogs, &cp)
	s.saveFallbackLocked()
	return nil
}

func (s *Store) ListDnsLogs(limit int) ([]*model.DnsChangeLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if s.isMySQL {
		rows, err := s.db.Query(
			"SELECT id, rule_id, rule_name, domain, old_ip, new_ip, created_at FROM dns_change_logs ORDER BY id DESC LIMIT ?",
			limit,
		)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var list []*model.DnsChangeLog
		for rows.Next() {
			l := &model.DnsChangeLog{}
			var oldIP sql.NullString
			if err := rows.Scan(&l.ID, &l.RuleID, &l.RuleName, &l.Domain, &oldIP, &l.NewIP, &l.CreatedAt); err != nil {
				return nil, err
			}
			if oldIP.Valid {
				l.OldIP = &oldIP.String
			}
			list = append(list, l)
		}
		return list, nil
	}

	res := make([]*model.DnsChangeLog, 0, len(s.memLogs))
	for i := len(s.memLogs) - 1; i >= 0 && len(res) < limit; i-- {
		cp := *s.memLogs[i]
		res = append(res, &cp)
	}
	return res, nil
}

