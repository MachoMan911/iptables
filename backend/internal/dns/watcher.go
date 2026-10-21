package dns

import (
	"log"
	"sync"
	"time"

	"wallfacer-forwarder/internal/config"
	"wallfacer-forwarder/internal/database"
	"wallfacer-forwarder/internal/iptables"
	"wallfacer-forwarder/internal/model"
)

type Watcher struct {
	mu              sync.Mutex
	IntervalSeconds int
	LastRunAt       *time.Time
	IsRunning       bool
	stopCh          chan struct{}
}

var GlobalWatcher = &Watcher{
	IntervalSeconds: 60,
}

func (w *Watcher) Start() {
	w.mu.Lock()
	if w.IsRunning {
		w.mu.Unlock()
		return
	}
	if config.Global.DnsWatcher.IntervalSeconds >= 5 {
		w.IntervalSeconds = config.Global.DnsWatcher.IntervalSeconds
	}
	w.IsRunning = true
	w.stopCh = make(chan struct{})
	w.mu.Unlock()

	go func() {
		for {
			w.mu.Lock()
			interval := time.Duration(w.IntervalSeconds) * time.Second
			w.mu.Unlock()

			select {
			case <-time.After(interval):
				w.CheckAllDomains()
			case <-w.stopCh:
				return
			}
		}
	}()
}

func (w *Watcher) SetInterval(seconds int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if seconds >= 5 {
		w.IntervalSeconds = seconds
	}
}

func (w *Watcher) CheckAllDomains() map[string]interface{} {
	now := time.Now()
	w.mu.Lock()
	w.LastRunAt = &now
	w.mu.Unlock()

	rules, err := database.DB.ListRules()
	if err != nil {
		return map[string]interface{}{
			"checked_at":        now,
			"checked_count":     0,
			"changed_count":     0,
			"error_count":       1,
			"iptables_resynced": false,
		}
	}

	checkedCount := 0
	changedCount := 0
	errorCount := 0
	needResync := false

	for _, rule := range rules {
		if !rule.IsDomain {
			continue
		}
		checkedCount++
		newIP, err := iptables.ResolveHostIPv4(rule.TargetHost)
		rule.LastCheckedAt = &now
		if err != nil {
			errorCount++
			errStr := err.Error()
			rule.LastError = &errStr
			_ = database.DB.UpdateRule(rule)
			continue
		}

		rule.LastError = nil
		oldIPVal := ""
		if rule.ResolvedIP != nil {
			oldIPVal = *rule.ResolvedIP
		}

		// 用最新解析出的 IP 覆盖规则中的生效 IP 配置
		rule.ResolvedIP = &newIP
		if rule.Enabled {
			needResync = true
		}

		if oldIPVal != newIP {
			changedCount++
			var oldPtr *string
			if oldIPVal != "" {
				cp := oldIPVal
				oldPtr = &cp
			}
			rule.LastChangedAt = &now
			_ = database.DB.AddDnsLog(&model.DnsChangeLog{
				RuleID:    rule.ID,
				RuleName:  rule.Name,
				Domain:    rule.TargetHost,
				OldIP:     oldPtr,
				NewIP:     newIP,
				CreatedAt: now,
			})
			log.Printf("检测到规则 [%s] 域名 %s IP 变更并覆盖配置: %s -> %s", rule.Name, rule.TargetHost, oldIPVal, newIP)
		}
		_ = database.DB.UpdateRule(rule)
	}

	if needResync {
		updatedRules, _ := database.DB.ListRules()
		_, _ = iptables.Mgr.SyncAllRules(updatedRules)
	}

	return map[string]interface{}{
		"checked_at":        now,
		"checked_count":     checkedCount,
		"changed_count":     changedCount,
		"error_count":       errorCount,
		"iptables_resynced": needResync,
	}
}

