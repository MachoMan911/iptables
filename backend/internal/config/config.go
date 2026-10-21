package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"sync"

	"gopkg.in/yaml.v3"
)

var validDBNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_$-]{1,64}$`)

type ServerConfig struct {
	Host           string `yaml:"host" json:"host"`
	Port           int    `yaml:"port" json:"port"`
	JWTSecret      string `yaml:"jwt_secret" json:"-"`
	JWTExpireHours int    `yaml:"jwt_expire_hours" json:"jwt_expire_hours"`
}

type MySQLConfig struct {
	Host     string `yaml:"host" json:"host"`
	Port     int    `yaml:"port" json:"port"`
	User     string `yaml:"user" json:"user"`
	Password string `yaml:"password" json:"password,omitempty"`
	Database string `yaml:"database" json:"database"`
	Charset  string `yaml:"charset" json:"charset"`
}

type AuthConfig struct {
	InitialAdminUser      string `yaml:"initial_admin_user" json:"initial_admin_user"`
	InitialAdminPassword  string `yaml:"initial_admin_password" json:"-"`
	MaxFailedAttempts     int    `yaml:"max_failed_attempts" json:"max_failed_attempts"`
	LockoutMinutes        int    `yaml:"lockout_minutes" json:"lockout_minutes"`
	SessionTimeoutMinutes int    `yaml:"session_timeout_minutes" json:"session_timeout_minutes"`
}

type DnsWatcherConfig struct {
	IntervalSeconds int `yaml:"interval_seconds" json:"interval_seconds"`
}

type IptablesConfig struct {
	AutoEnableIPForward bool   `yaml:"auto_enable_ip_forward" json:"auto_enable_ip_forward"`
	ChainPrefix         string `yaml:"chain_prefix" json:"chain_prefix"`
	DryRun              bool   `yaml:"dry_run" json:"dry_run"`
}

type AppConfig struct {
	mu         sync.RWMutex     `yaml:"-" json:"-"`
	ConfigPath string           `yaml:"-" json:"-"`
	Server     ServerConfig     `yaml:"server" json:"server"`
	MySQL      MySQLConfig      `yaml:"mysql" json:"mysql"`
	Auth       AuthConfig       `yaml:"auth" json:"auth"`
	DnsWatcher DnsWatcherConfig `yaml:"dns_watcher" json:"dns_watcher"`
	Iptables   IptablesConfig   `yaml:"iptables" json:"iptables"`
}

var Global = &AppConfig{
	ConfigPath: "config.yaml",
	Server: ServerConfig{
		Host:           "0.0.0.0",
		Port:           8080,
		JWTSecret:      "wallfacer-grade3-jwt-secret-key-2026",
		JWTExpireHours: 24,
	},
	MySQL: MySQLConfig{
		Host:     "127.0.0.1",
		Port:     3306,
		User:     "root",
		Password: "your_mysql_password",
		Database: "wallfacer_forwarder",
		Charset:  "utf8mb4",
	},
	Auth: AuthConfig{
		InitialAdminUser:      "admin",
		InitialAdminPassword:  "Admin@2026!",
		MaxFailedAttempts:     5,
		LockoutMinutes:        15,
		SessionTimeoutMinutes: 30,
	},
	DnsWatcher: DnsWatcherConfig{
		IntervalSeconds: 60,
	},
	Iptables: IptablesConfig{
		AutoEnableIPForward: true,
		ChainPrefix:         "IPT_FWD",
		DryRun:              false,
	},
}

func ValidateDatabaseName(dbName string) error {
	if !validDBNameRegex.MatchString(dbName) {
		return fmt.Errorf("自定义数据库名 [%s] 格式不合法（仅允许字母、数字、下划线、中划线，长度 1~64 位）", dbName)
	}
	return nil
}

func Load(path string) error {
	Global.mu.Lock()
	defer Global.mu.Unlock()

	if path != "" {
		Global.ConfigPath = path
	}
	if data, err := os.ReadFile(Global.ConfigPath); err == nil {
		_ = yaml.Unmarshal(data, Global)
	}

	// 支持环境变量覆盖
	if v := os.Getenv("SERVER_HOST"); v != "" {
		Global.Server.Host = v
	}
	if v := os.Getenv("SERVER_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			Global.Server.Port = p
		}
	}
	if v := os.Getenv("MYSQL_HOST"); v != "" {
		Global.MySQL.Host = v
	}
	if v := os.Getenv("MYSQL_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			Global.MySQL.Port = p
		}
	}
	if v := os.Getenv("MYSQL_USER"); v != "" {
		Global.MySQL.User = v
	}
	if v := os.Getenv("MYSQL_PASSWORD"); v != "" {
		Global.MySQL.Password = v
	}
	if v := os.Getenv("MYSQL_DATABASE"); v != "" {
		Global.MySQL.Database = v
	}
	if Global.MySQL.Charset == "" {
		Global.MySQL.Charset = "utf8mb4"
	}
	return ValidateDatabaseName(Global.MySQL.Database)
}

func UpdateMySQLConfig(newCfg MySQLConfig) error {
	if err := ValidateDatabaseName(newCfg.Database); err != nil {
		return err
	}
	Global.mu.Lock()
	defer Global.mu.Unlock()

	if newCfg.Host != "" {
		Global.MySQL.Host = newCfg.Host
	}
	if newCfg.Port > 0 {
		Global.MySQL.Port = newCfg.Port
	}
	if newCfg.User != "" {
		Global.MySQL.User = newCfg.User
	}
	if newCfg.Password != "" {
		Global.MySQL.Password = newCfg.Password
	}
	Global.MySQL.Database = newCfg.Database
	if newCfg.Charset != "" {
		Global.MySQL.Charset = newCfg.Charset
	}

	out, err := yaml.Marshal(Global)
	if err == nil {
		_ = os.WriteFile(Global.ConfigPath, out, 0600)
	}
	return nil
}

