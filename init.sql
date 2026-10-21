-- ============================================================================
-- 面壁者转发 (Wallfacer Forwarder) - MySQL 表结构初始化脚本
-- 说明：
-- 1. 本脚本不绑定固定数据库名，支持任意自定义数据库名（例如 wallfacer_forwarder）。
-- 2. 手动导入方式：
--    mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS \`自定义数据库名\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
--    mysql -u root -p 自定义数据库名 < init.sql
-- 3. Go 后端启动或在页面修改数据库配置时，也会根据您自定义的数据库名自动执行建库与建表。
-- ============================================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- 1. 系统认证用户表（满足网络安全等级保护三级身份鉴别要求）
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `username` VARCHAR(64) NOT NULL UNIQUE COMMENT '管理员用户名',
    `password_hash` VARCHAR(255) NOT NULL COMMENT 'PBKDF2-HMAC-SHA256 加盐密码哈希',
    `failed_attempts` INT NOT NULL DEFAULT 0 COMMENT '连续登录失败次数（等保三级防暴力破解）',
    `locked_until` DATETIME DEFAULT NULL COMMENT '账号锁定截止时间',
    `password_changed_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '最近一次密码修改时间',
    `last_login_at` DATETIME DEFAULT NULL COMMENT '最近一次成功登录时间',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='等保三级系统认证用户表';

-- 2. 端口与域名转发规则表（含上下行累计流量与本机网卡 SNAT 源 IP）
CREATE TABLE IF NOT EXISTS `forward_rules` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `name` VARCHAR(128) NOT NULL COMMENT '规则名称/备注',
    `protocol` VARCHAR(16) NOT NULL DEFAULT 'tcp+udp' COMMENT '协议类型: tcp, udp, tcp+udp',
    `listen_port` INT NOT NULL COMMENT '本机监听端口',
    `target_host` VARCHAR(255) NOT NULL COMMENT '目标地址（支持域名或IPv4地址）',
    `target_port` INT NOT NULL COMMENT '目标端口',
    `is_domain` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '目标是否为域名: 1是, 0否',
    `resolved_ip` VARCHAR(64) DEFAULT NULL COMMENT '当前解析生效的目标IPv4地址',
    `snat_ip` VARCHAR(64) DEFAULT NULL COMMENT '本机网卡回程SNAT源IP',
    `up_bytes` BIGINT NOT NULL DEFAULT 0 COMMENT '累计上行流量字节数',
    `down_bytes` BIGINT NOT NULL DEFAULT 0 COMMENT '累计下行流量字节数',
    `enabled` TINYINT(1) NOT NULL DEFAULT 1 COMMENT '是否启用: 1启用, 0停用',
    `last_checked_at` DATETIME DEFAULT NULL COMMENT '最近一次域名解析检测时间',
    `last_changed_at` DATETIME DEFAULT NULL COMMENT '最近一次域名IP变更时间',
    `last_error` VARCHAR(512) DEFAULT NULL COMMENT '最近一次解析或iptables执行错误信息',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY `uk_listen_port_proto` (`listen_port`, `protocol`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='iptables端口与域名转发规则表';

-- 3. 域名解析 IP 变更与自动同步日志表
CREATE TABLE IF NOT EXISTS `dns_change_logs` (
    `id` INT AUTO_INCREMENT PRIMARY KEY,
    `rule_id` INT NOT NULL COMMENT '关联规则ID',
    `rule_name` VARCHAR(128) NOT NULL COMMENT '规则名称',
    `domain` VARCHAR(255) NOT NULL COMMENT '目标域名',
    `old_ip` VARCHAR(64) DEFAULT NULL COMMENT '变更前IP',
    `new_ip` VARCHAR(64) NOT NULL COMMENT '变更后新IP',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX `idx_rule_id` (`rule_id`),
    INDEX `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='域名IP变更及自动更新日志表';

SET FOREIGN_KEY_CHECKS = 1;
