package model

import "time"

type User struct {
	ID                int        `json:"id"`
	Username          string     `json:"username"`
	PasswordHash      string     `json:"password_hash"`
	FailedAttempts    int        `json:"failed_attempts"`
	LockedUntil       *time.Time `json:"locked_until"`
	PasswordChangedAt time.Time  `json:"password_changed_at"`
	LastLoginAt       *time.Time `json:"last_login_at"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type ForwardRule struct {
	ID            int        `json:"id"`
	Name          string     `json:"name"`
	Protocol      string     `json:"protocol"`
	ListenPort    int        `json:"listen_port"`
	TargetHost    string     `json:"target_host"`
	TargetPort    int        `json:"target_port"`
	IsDomain      bool       `json:"is_domain"`
	ResolvedIP    *string    `json:"resolved_ip"`
	SnatIP        *string    `json:"snat_ip"`
	UpBytes       int64      `json:"up_bytes"`
	DownBytes     int64      `json:"down_bytes"`
	TotalBytes    int64      `json:"total_bytes"`
	UpSpeed       float64    `json:"up_speed"`
	DownSpeed     float64    `json:"down_speed"`
	Enabled       bool       `json:"enabled"`
	LastCheckedAt *time.Time `json:"last_checked_at"`
	LastChangedAt *time.Time `json:"last_changed_at"`
	LastError     *string    `json:"last_error"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type DnsChangeLog struct {
	ID        int       `json:"id"`
	RuleID    int       `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	Domain    string    `json:"domain"`
	OldIP     *string   `json:"old_ip"`
	NewIP     string    `json:"new_ip"`
	CreatedAt time.Time `json:"created_at"`
}

type LoginRequest struct {
	EncryptedCredentials string `json:"encrypted_credentials"`
	Nonce                string `json:"nonce"`
}

type PasswordChangeRequest struct {
	EncryptedOldPassword string `json:"encrypted_old_password"`
	EncryptedNewPassword string `json:"encrypted_new_password"`
	Nonce                string `json:"nonce"`
}

type RuleMutationRequest struct {
	Name       string  `json:"name"`
	Protocol   string  `json:"protocol"`
	ListenPort int     `json:"listen_port"`
	TargetHost string  `json:"target_host"`
	TargetPort int     `json:"target_port"`
	SnatIP     *string `json:"snat_ip"`
	Enabled    bool    `json:"enabled"`
}

type DnsIntervalRequest struct {
	IntervalSeconds int `json:"interval_seconds"`
}

type DBConfigUpdateRequest struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Database string `json:"database"`
}

