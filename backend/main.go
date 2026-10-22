package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"wallfacer-forwarder/internal/config"
	"wallfacer-forwarder/internal/database"
	"wallfacer-forwarder/internal/dns"
	"wallfacer-forwarder/internal/handler"
	"wallfacer-forwarder/internal/iptables"
)

func main() {
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)

	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "config.yaml"
		if _, err := os.Stat(cfgPath); err != nil {
			altCfg := filepath.Join(exeDir, "config.yaml")
			if _, err2 := os.Stat(altCfg); err2 == nil {
				cfgPath = altCfg
			}
		}
	}
	if err := config.Load(cfgPath); err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	if err := database.DB.Init(); err != nil {
		log.Printf("初始化数据库提示: %v", err)
	}

	// 启动时做一次域名检测并同步所有规则
	dns.GlobalWatcher.CheckAllDomains()
	if rules, err := database.DB.ListRules(); err == nil {
		_, _ = iptables.Mgr.SyncAllRules(rules)
	}

	// 启动后台域名定时检测器
	dns.GlobalWatcher.Start()

	// 启动后台 1.5 秒实时流量与上下行网速采样协程
	go func() {
		iptables.Mgr.SampleTraffic()
		ticker := time.NewTicker(1500 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			iptables.Mgr.SampleTraffic()
		}
	}()

	candidates := []string{
		filepath.Join(exeDir, "frontend", "dist"),
		filepath.Join(exeDir, "..", "frontend", "dist"),
		filepath.Join("..", "frontend", "dist"),
		filepath.Join("frontend", "dist"),
		filepath.Join(exeDir, "frontend"),
		filepath.Join(exeDir, "..", "frontend"),
		filepath.Join("..", "frontend"),
		"./frontend",
	}
	frontendDir := "./frontend"
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "index.html")); err == nil {
			frontendDir = c
			break
		}
	}

	addr := fmt.Sprintf("%s:%d", config.Global.Server.Host, config.Global.Server.Port)
	log.Printf("面壁者转发 (Go Backend) 已启动，监听地址: http://%s (当前数据库: %s)", addr, config.Global.MySQL.Database)
	if err := http.ListenAndServe(addr, handler.NewRouter(frontendDir)); err != nil {
		log.Fatalf("服务异常退出: %v", err)
	}
}

