#!/usr/bin/env bash
# ==============================================================================
# MySQL 8.4 LTS 一键自动化部署脚本 (面壁者转发 Wallfacer Forwarder 配套脚本)
# 支持环境:
#   1. Linux 原生安装 (Ubuntu / Debian / CentOS / RHEL / Rocky / AlmaLinux 等)
#   2. Docker 容器化安装 (全平台 Linux / macOS，镜像 mysql:8.4)
#   3. macOS Homebrew 原生安装 (mysql@8.4)
# 核心功能:
#   - 自动配置官方 MySQL 8.4 LTS 软件源或 Docker 容器并完成安装启动
#   - 自动生成符合等保三级与 MySQL 8.4 强口令策略的随机密码（也支持手动指定）
#   - 自动初始化业务数据库并导入项目 init.sql 表结构
#   - 自动同步更新项目 config.yaml 中的 MySQL 账号密码配置（可跳过）
#   - 部署完成后在终端高亮输出完整的 MySQL 账号、密码、连接命令与 DSN
# ==============================================================================

set -euo pipefail

# 终端颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 生成符合强口令策略的随机密码 (包含大小写字母、数字、特殊符号，避免引起 Shell 转义歧义的字符)
generate_strong_password() {
    local rand_str=""
    if command -v openssl >/dev/null 2>&1; then
        rand_str="$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 10)"
    else
        rand_str="$(date +%s%N | sha256sum | base64 | tr -dc 'A-Za-z0-9' | head -c 10)"
    fi
    # 确保必含大写、小写、数字与安全特殊字符 (@#_)
    echo "My84@${rand_str}#9aA"
}

# 默认配置参数（支持环境变量或命令行参数覆盖）
DEPLOY_MODE="${DEPLOY_MODE:-auto}"                 # auto | native | docker
MYSQL_VERSION="8.4"
MYSQL_BIND_HOST="${MYSQL_BIND_HOST:-127.0.0.1}"    # 默认仅监听本地保障安全，可通过 --bind 0.0.0.0 开放远程
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_ROOT_USER="root"
MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD:-}"     # 为空时自动生成高强度随机密码
MYSQL_APP_USER="${MYSQL_APP_USER:-wallfacer}"      # 业务专属账号（也可设为 root）
MYSQL_APP_PASSWORD="${MYSQL_APP_PASSWORD:-}"       # 为空时自动生成高强度随机密码
MYSQL_DATABASE="${MYSQL_DATABASE:-wallfacer_forwarder}"
MYSQL_DATA_DIR="${MYSQL_DATA_DIR:-/opt/mysql84}"   # Docker 模式数据持久化目录
CONTAINER_NAME="${CONTAINER_NAME:-wallfacer-mysql84}"
SYNC_CONFIG="${SYNC_CONFIG:-true}"                 # 是否自动将生成的账号密码回写到项目 config.yaml
ALLOW_REMOTE="${ALLOW_REMOTE:-false}"              # 是否允许远程主机 (%) 连接
NON_INTERACTIVE="${NON_INTERACTIVE:-false}"
CREDENTIAL_FILE="${CREDENTIAL_FILE:-${PROJECT_ROOT}/.mysql84_credentials}"

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*" >&2; exit 1; }

usage() {
    cat <<EOF
用法: $(basename "$0") [命令] [选项]

可用命令:
  install          一键部署 MySQL 8.4 LTS、初始化库表并输出账号密码（默认命令）
  credentials      查看最近一次部署生成的 MySQL 8.4 账号密码信息
  reset-password   重置 MySQL 8.4 账号密码并输出新密码
  status           查看 MySQL 8.4 服务运行状态与连通性
  restart          重启 MySQL 8.4 服务
  stop             停止 MySQL 8.4 服务
  logs             查看 MySQL 8.4 运行日志
  uninstall        停止并卸载 MySQL 8.4 容器或服务

可选参数 (用于 install 命令):
  -y, --yes                 非交互静默部署（自动生成随机强密码，无需人工干预）
  --mode <auto|native|docker> 部署模式:
                              auto   - 自动选择（Linux 优先系统原生安装，无源或指定时使用 Docker）
                              native - 使用操作系统包管理器安装 MySQL 8.4 LTS 原生服务
                              docker - 使用官方 mysql:8.4 容器部署（推荐跨发行版/快速隔离环境）
  --port <port>             MySQL 监听端口 (默认: 3306)
  --bind <ip>               MySQL 绑定监听地址 (默认: 127.0.0.1，如需外网访问可传 0.0.0.0)
  --root-pass <password>    指定 root 账号密码（不传则自动生成 16 位强随机密码）
  --db-user <username>      指定业务数据库账号 (默认: wallfacer，也可传 root)
  --db-pass <password>      指定业务数据库密码（不传则自动生成 16 位强随机密码）
  --db-name <database>      自动创建并初始化的数据库名 (默认: wallfacer_forwarder)
  --data-dir <path>         Docker 模式持久化目录 (默认: /opt/mysql84)
  --allow-remote            允许从任意远程 IP (%) 登录数据库
  --no-sync-config          不自动更新项目中的 config.yaml 配置文件
  -h, --help                显示此帮助说明

示例:
  # 1. 全自动静默一键部署 MySQL 8.4（自动生成强密码并在结尾输出账号密码）
  sudo ./deploy_mysql84.sh -y

  # 2. 使用 Docker 模式一键部署 MySQL 8.4
  sudo ./deploy_mysql84.sh install -y --mode docker

  # 3. 自定义数据库名与密码一键部署
  sudo ./deploy_mysql84.sh install -y \\
    --db-name my_forwarder_db \\
    --db-user wallfacer \\
    --db-pass 'Wallfacer@2026!'

  # 4. 随时重新查看已部署的账号密码
  ./deploy_mysql84.sh credentials
EOF
}

# 解析命令行参数
COMMAND="install"
if [[ $# -gt 0 ]]; then
    case "$1" in
        install|credentials|info|reset-password|status|restart|stop|logs|uninstall)
            COMMAND="$1"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
    esac
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes)           NON_INTERACTIVE="true"; shift ;;
        --mode)             DEPLOY_MODE="$2"; shift 2 ;;
        --port)             MYSQL_PORT="$2"; shift 2 ;;
        --bind)             MYSQL_BIND_HOST="$2"; shift 2 ;;
        --root-pass)        MYSQL_ROOT_PASSWORD="$2"; shift 2 ;;
        --db-user)          MYSQL_APP_USER="$2"; shift 2 ;;
        --db-pass)          MYSQL_APP_PASSWORD="$2"; shift 2 ;;
        --db-name)          MYSQL_DATABASE="$2"; shift 2 ;;
        --data-dir)         MYSQL_DATA_DIR="$2"; shift 2 ;;
        --allow-remote)     ALLOW_REMOTE="true"; MYSQL_BIND_HOST="0.0.0.0"; shift ;;
        --no-sync-config)   SYNC_CONFIG="false"; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  error "未知参数: $1 (使用 --help 查看帮助)" ;;
    esac
done

# 检测操作系统与发行版
OS_TYPE="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_RAW="$(uname -m)"
DISTRO_ID="unknown"
DISTRO_VERSION_ID=""

if [[ "${OS_TYPE}" == "linux" ]] && [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    DISTRO_VERSION_ID="${VERSION_ID:-}"
fi

# 交互式向导（未传 -y 时支持回车使用自动生成的随机密码）
prompt_interactive() {
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        return
    fi
    echo -e "\n${CYAN}================ MySQL 8.4 LTS 一键自动化部署向导 ================${NC}"
    read -r -p "1. 部署模式 [auto / native / docker，默认 ${DEPLOY_MODE}]: " input_mode
    DEPLOY_MODE="${input_mode:-${DEPLOY_MODE}}"

    read -r -p "2. MySQL 监听端口 [${MYSQL_PORT}]: " input_port
    MYSQL_PORT="${input_port:-${MYSQL_PORT}}"

    read -r -p "3. 初始化数据库名称 [${MYSQL_DATABASE}]: " input_db
    MYSQL_DATABASE="${input_db:-${MYSQL_DATABASE}}"

    read -r -p "4. 业务数据库用户名 [${MYSQL_APP_USER}]: " input_user
    MYSQL_APP_USER="${input_user:-${MYSQL_APP_USER}}"

    read -r -s -p "5. root 密码 [直接回车将自动生成 16 位强随机密码]: " input_root_pass
    echo ""
    if [[ -n "${input_root_pass}" ]]; then
        MYSQL_ROOT_PASSWORD="${input_root_pass}"
    fi

    if [[ "${MYSQL_APP_USER}" != "root" ]]; then
        read -r -s -p "6. 业务账号 (${MYSQL_APP_USER}) 密码 [直接回车将自动生成 16 位强随机密码]: " input_app_pass
        echo ""
        if [[ -n "${input_app_pass}" ]]; then
            MYSQL_APP_PASSWORD="${input_app_pass}"
        fi
    fi
    echo -e "${CYAN}==================================================================${NC}\n"
}

# 确保密码已生成
ensure_passwords() {
    if [[ -z "${MYSQL_ROOT_PASSWORD}" ]]; then
        MYSQL_ROOT_PASSWORD="$(generate_strong_password)"
    fi
    if [[ "${MYSQL_APP_USER}" == "root" ]]; then
        MYSQL_APP_PASSWORD="${MYSQL_ROOT_PASSWORD}"
    elif [[ -z "${MYSQL_APP_PASSWORD}" ]]; then
        MYSQL_APP_PASSWORD="$(generate_strong_password)"
    fi
}

# 选择最终部署模式 (native 或 docker)
resolve_deploy_mode() {
    if [[ "${DEPLOY_MODE}" == "docker" ]]; then
        if ! command -v docker >/dev/null 2>&1; then
            error "已指定 --mode docker，但当前系统未安装 Docker。请先安装 Docker 或改用 --mode native"
        fi
        ACTIVE_MODE="docker"
        return
    fi

    if [[ "${DEPLOY_MODE}" == "native" ]]; then
        ACTIVE_MODE="native"
        return
    fi

    # auto 模式自动判断
    if [[ "${OS_TYPE}" == "darwin" ]]; then
        if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
            ACTIVE_MODE="docker"
        elif command -v brew >/dev/null 2>&1; then
            ACTIVE_MODE="native"
        else
            error "macOS 环境请先安装 Homebrew (brew) 或启动 Docker Desktop"
        fi
    elif [[ "${OS_TYPE}" == "linux" ]]; then
        case "${DISTRO_ID}" in
            ubuntu|debian|centos|rhel|rocky|almalinux|ol|fedora|anolis|opencloudos)
                ACTIVE_MODE="native"
                ;;
            *)
                if command -v docker >/dev/null 2>&1; then
                    info "当前 Linux 发行版 (${DISTRO_ID}) 优先采用 Docker 官方镜像部署 MySQL 8.4"
                    ACTIVE_MODE="docker"
                else
                    ACTIVE_MODE="native"
                fi
                ;;
        esac
    else
        error "暂不支持的操作系统: ${OS_TYPE}"
    fi
}

# ==============================================================================
# 模式 A: Docker 部署 MySQL 8.4 LTS
# ==============================================================================
deploy_mysql_docker() {
    info "正在使用 Docker 模式部署 MySQL 8.4 LTS (容器名: ${CONTAINER_NAME})..."

    mkdir -p "${MYSQL_DATA_DIR}/data" "${MYSQL_DATA_DIR}/conf" "${MYSQL_DATA_DIR}/logs"

    # 生成 MySQL 8.4 优化配置文件
    cat > "${MYSQL_DATA_DIR}/conf/my.cnf" <<EOF
[mysqld]
port = 3306
bind-address = 0.0.0.0
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
default-time-zone = '+08:00'
max_connections = 1000
max_connect_errors = 1000
innodb_buffer_pool_size = 256M
innodb_log_file_size = 64M
innodb_flush_log_at_trx_commit = 1
slow_query_log = 1
long_query_time = 2
log_error_verbosity = 2
skip-name-resolve

[client]
default-character-set = utf8mb4
EOF

    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        warn "检测到已存在同名容器 ${CONTAINER_NAME}，正在移除旧容器（保留数据卷或重新配置）..."
        docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    fi

    local port_mapping="${MYSQL_BIND_HOST}:${MYSQL_PORT}:3306"
    if [[ "${MYSQL_BIND_HOST}" == "0.0.0.0" ]]; then
        port_mapping="${MYSQL_PORT}:3306"
    fi

    info "正在拉取并启动 mysql:8.4 官方 LTS 容器..."
    docker run -d \
        --name "${CONTAINER_NAME}" \
        --restart always \
        -p "${port_mapping}" \
        -e MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD}" \
        -e MYSQL_DATABASE="${MYSQL_DATABASE}" \
        -e TZ="Asia/Shanghai" \
        -v "${MYSQL_DATA_DIR}/data:/var/lib/mysql" \
        -v "${MYSQL_DATA_DIR}/conf/my.cnf:/etc/mysql/conf.d/custom.cnf:ro" \
        mysql:8.4 >/dev/null

    info "正在等待 MySQL 8.4 实例完成初始化就绪..."
    local retries=60
    while [[ ${retries} -gt 0 ]]; do
        if docker exec "${CONTAINER_NAME}" mysqladmin ping -h 127.0.0.1 -uroot -p"${MYSQL_ROOT_PASSWORD}" --silent >/dev/null 2>&1; then
            break
        fi
        sleep 2
        retries=$((retries - 1))
    done

    if [[ ${retries} -le 0 ]]; then
        error "MySQL 8.4 容器启动超时，请执行 'docker logs ${CONTAINER_NAME}' 检查原因"
    fi

    # 确保 root 密码与业务账号权限配置到位（兼容数据目录已存在的情况）
    local host_scope="%"
    local init_sql_cmd="
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';
ALTER USER 'root'@'%' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';
CREATE DATABASE IF NOT EXISTS \`${MYSQL_DATABASE}\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
"
    if [[ "${MYSQL_APP_USER}" != "root" ]]; then
        init_sql_cmd+="
CREATE USER IF NOT EXISTS '${MYSQL_APP_USER}'@'localhost' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
ALTER USER '${MYSQL_APP_USER}'@'localhost' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.* TO '${MYSQL_APP_USER}'@'localhost';
CREATE USER IF NOT EXISTS '${MYSQL_APP_USER}'@'${host_scope}' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
ALTER USER '${MYSQL_APP_USER}'@'${host_scope}' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.* TO '${MYSQL_APP_USER}'@'${host_scope}';
"
    fi
    init_sql_cmd+="FLUSH PRIVILEGES;"

    docker exec -i "${CONTAINER_NAME}" mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -e "${init_sql_cmd}" >/dev/null 2>&1

    # 导入项目 init.sql 表结构
    if [[ -f "${PROJECT_ROOT}/init.sql" ]]; then
        info "正在向数据库 [${MYSQL_DATABASE}] 导入项目表结构 (init.sql)..."
        docker exec -i "${CONTAINER_NAME}" mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" "${MYSQL_DATABASE}" < "${PROJECT_ROOT}/init.sql"
        success "项目表结构 (users / forward_rules / dns_change_logs) 导入完成"
    fi

    success "Docker 模式 MySQL 8.4 LTS 部署完成"
}

# ==============================================================================
# 模式 B: Linux / macOS 原生系统安装 MySQL 8.4 LTS
# ==============================================================================
install_mysql84_rhel() {
    info "检测到 RHEL/CentOS/Rocky/AlmaLinux 系列系统 (${DISTRO_ID} ${DISTRO_VERSION_ID})，正在配置 MySQL 8.4 LTS 官方 YUM/DNF 源..."
    local el_ver="${DISTRO_VERSION_ID%%.*}"
    if [[ "${el_ver}" != "8" && "${el_ver}" != "9" ]]; then
        el_ver="9"
    fi

    local repo_rpm="mysql84-community-release-el${el_ver}-1.noarch.rpm"
    local repo_url="https://repo.mysql.com/${repo_rpm}"

    # 禁用系统自带的 mysql 模块以防屏蔽官方 8.4 包
    if command -v dnf >/dev/null 2>&1; then
        dnf module disable -y mysql >/dev/null 2>&1 || true
        dnf install -y "${repo_url}" >/dev/null 2>&1 || rpm -Uvh --force "${repo_url}"
        rpm --import https://repo.mysql.com/RPM-GPG-KEY-mysql-2023 >/dev/null 2>&1 || true
        info "正在通过 DNF 安装 mysql-community-server (8.4 LTS)..."
        dnf install -y mysql-community-server
    else
        yum install -y "${repo_url}" >/dev/null 2>&1 || rpm -Uvh --force "${repo_url}"
        rpm --import https://repo.mysql.com/RPM-GPG-KEY-mysql-2023 >/dev/null 2>&1 || true
        info "正在通过 YUM 安装 mysql-community-server (8.4 LTS)..."
        yum install -y mysql-community-server
    fi
}

install_mysql84_debian_ubuntu() {
    info "检测到 Debian/Ubuntu 系列系统 (${DISTRO_ID} ${DISTRO_VERSION_ID})，正在配置 MySQL 8.4 LTS 官方 APT 源..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null
    apt-get install -y curl wget gnupg lsb-release debconf-utils >/dev/null

    local codename
    codename="$(lsb_release -cs 2>/dev/null || echo "")"
    local keyring="/usr/share/keyrings/mysql-apt-keyring.gpg"
    curl -fsSL https://repo.mysql.com/RPM-GPG-KEY-mysql-2023 | gpg --dearmor --yes -o "${keyring}"

    cat > /etc/apt/sources.list.d/mysql84-lts.list <<EOF
deb [signed-by=${keyring}] http://repo.mysql.com/apt/${DISTRO_ID}/ ${codename} mysql-8.4-lts
deb [signed-by=${keyring}] http://repo.mysql.com/apt/${DISTRO_ID}/ ${codename} mysql-tools
EOF

    # 预置非交互安装密码
    debconf-set-selections <<EOF
mysql-community-server mysql-community-server/root-pass password ${MYSQL_ROOT_PASSWORD}
mysql-community-server mysql-community-server/re-root-pass password ${MYSQL_ROOT_PASSWORD}
EOF

    apt-get update -y >/dev/null
    info "正在通过 APT 安装 mysql-community-server (8.4 LTS)..."
    apt-get install -y mysql-community-server
}

install_mysql84_macos() {
    info "检测到 macOS 环境，正在通过 Homebrew 安装 mysql@8.4..."
    brew install mysql@8.4
    brew services start mysql@8.4
    export PATH="/opt/homebrew/opt/mysql@8.4/bin:/usr/local/opt/mysql@8.4/bin:${PATH}"
}

configure_native_my_cnf() {
    if [[ "${OS_TYPE}" != "linux" ]]; then
        return
    fi
    local cnf_file="/etc/my.cnf"
    if [[ -d /etc/mysql/mysql.conf.d ]]; then
        cnf_file="/etc/mysql/mysql.conf.d/z99-wallfacer-mysql84.cnf"
    elif [[ -d /etc/my.cnf.d ]]; then
        cnf_file="/etc/my.cnf.d/z99-wallfacer-mysql84.cnf"
    fi

    info "正在写入 MySQL 8.4 生产环境配置 (${cnf_file})..."
    cat > "${cnf_file}" <<EOF
[mysqld]
port = ${MYSQL_PORT}
bind-address = ${MYSQL_BIND_HOST}
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
default-time-zone = '+08:00'
max_connections = 1000
max_connect_errors = 1000
innodb_buffer_pool_size = 256M
skip-name-resolve

[client]
default-character-set = utf8mb4
EOF
}

deploy_mysql_native() {
    if [[ "${OS_TYPE}" == "linux" ]] && [[ "${EUID}" -ne 0 ]]; then
        error "Linux 原生安装 MySQL 8.4 需要 root 权限，请使用: sudo ./deploy_mysql84.sh"
    fi

    if [[ "${OS_TYPE}" == "darwin" ]]; then
        install_mysql84_macos
    else
        case "${DISTRO_ID}" in
            ubuntu|debian)
                install_mysql84_debian_ubuntu
                ;;
            centos|rhel|rocky|almalinux|ol|fedora|anolis|opencloudos)
                install_mysql84_rhel
                ;;
            *)
                error "当前发行版 (${DISTRO_ID}) 暂不支持自动配置官方原生源，请添加 --mode docker 参数使用 Docker 部署 MySQL 8.4"
                ;;
        esac
    fi

    configure_native_my_cnf

    # 启动 systemd 服务
    local svc_name="mysqld"
    if [[ "${OS_TYPE}" == "linux" ]]; then
        if systemctl list-unit-files | grep -q "^mysql\.service"; then
            svc_name="mysql"
        fi
        systemctl daemon-reload
        systemctl enable "${svc_name}" >/dev/null 2>&1 || true
        systemctl restart "${svc_name}"
        success "systemd 服务 [${svc_name}] 已启动并设置开机自启"
    fi

    sleep 3

    # 执行原生 MySQL 8.4 账号密码初始化与建库
    info "正在配置 MySQL 8.4 账号密码与数据库权限..."
    local mysql_cmd=()
    if mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" -e "SELECT 1;" >/dev/null 2>&1; then
        mysql_cmd=(mysql -uroot -p"${MYSQL_ROOT_PASSWORD}")
    elif mysql -uroot -e "SELECT 1;" >/dev/null 2>&1; then
        mysql_cmd=(mysql -uroot)
    elif [[ -f /var/log/mysqld.log ]]; then
        local temp_pwd
        temp_pwd="$(grep 'temporary password' /var/log/mysqld.log | tail -n 1 | awk '{print $NF}' || true)"
        if [[ -n "${temp_pwd}" ]]; then
            info "已从 /var/log/mysqld.log 提取初始临时密码，正在修改为正式密码..."
            mysql --connect-expired-password -uroot -p"${temp_pwd}" \
                -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';"
            mysql_cmd=(mysql -uroot -p"${MYSQL_ROOT_PASSWORD}")
        fi
    fi

    if [[ ${#mysql_cmd[@]} -eq 0 ]]; then
        error "无法使用当前凭据登录本地 MySQL，若之前已安装过旧实例，请传入 --root-pass <原密码>"
    fi

    local sql_setup="
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';
CREATE DATABASE IF NOT EXISTS \`${MYSQL_DATABASE}\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
"
    if [[ "${ALLOW_REMOTE}" == "true" ]]; then
        sql_setup+="
CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';
ALTER USER 'root'@'%' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
"
    fi

    if [[ "${MYSQL_APP_USER}" != "root" ]]; then
        sql_setup+="
CREATE USER IF NOT EXISTS '${MYSQL_APP_USER}'@'localhost' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
ALTER USER '${MYSQL_APP_USER}'@'localhost' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.* TO '${MYSQL_APP_USER}'@'localhost';
CREATE USER IF NOT EXISTS '${MYSQL_APP_USER}'@'127.0.0.1' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
ALTER USER '${MYSQL_APP_USER}'@'127.0.0.1' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.* TO '${MYSQL_APP_USER}'@'127.0.0.1';
"
        if [[ "${ALLOW_REMOTE}" == "true" ]]; then
            sql_setup+="
CREATE USER IF NOT EXISTS '${MYSQL_APP_USER}'@'%' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
ALTER USER '${MYSQL_APP_USER}'@'%' IDENTIFIED BY '${MYSQL_APP_PASSWORD}';
GRANT ALL PRIVILEGES ON \`${MYSQL_DATABASE}\`.* TO '${MYSQL_APP_USER}'@'%';
"
        fi
    fi
    sql_setup+="FLUSH PRIVILEGES;"

    "${mysql_cmd[@]}" --connect-expired-password -e "${sql_setup}"

    if [[ -f "${PROJECT_ROOT}/init.sql" ]]; then
        info "正在向数据库 [${MYSQL_DATABASE}] 导入项目表结构 (init.sql)..."
        mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" "${MYSQL_DATABASE}" < "${PROJECT_ROOT}/init.sql"
        success "项目表结构 (users / forward_rules / dns_change_logs) 导入完成"
    fi
}

# ==============================================================================
# 自动同步项目 config.yaml 与保存凭据文件
# ==============================================================================
update_yaml_mysql_section() {
    local file="$1"
    if [[ ! -f "${file}" ]]; then
        return
    fi
    local connect_host="${MYSQL_BIND_HOST}"
    if [[ "${connect_host}" == "0.0.0.0" ]]; then
        connect_host="127.0.0.1"
    fi

    python3 - "${file}" "${connect_host}" "${MYSQL_PORT}" "${MYSQL_APP_USER}" "${MYSQL_APP_PASSWORD}" "${MYSQL_DATABASE}" <<'PYEOF' 2>/dev/null || true
import re, sys
path, host, port, user, pwd, db = sys.argv[1:7]
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

def replace_in_mysql(text):
    lines = text.splitlines(True)
    in_mysql = False
    out = []
    for line in lines:
        if re.match(r'^mysql:\s*$', line):
            in_mysql = True
            out.append(line)
            continue
        if in_mysql and re.match(r'^[a-zA-Z0-9_]+:\s*', line):
            in_mysql = False
        if in_mysql:
            line = re.sub(r'^(\s*host:\s*).*$', f'\\g<1>"{host}"', line)
            line = re.sub(r'^(\s*port:\s*).*$', f'\\g<1>{port}', line)
            line = re.sub(r'^(\s*user:\s*).*$', f'\\g<1>"{user}"', line)
            line = re.sub(r'^(\s*password:\s*).*$', f'\\g<1>"{pwd}"', line)
            line = re.sub(r'^(\s*database:\s*).*$', f'\\g<1>"{db}"', line)
        out.append(line)
    return ''.join(out)

with open(path, 'w', encoding='utf-8') as f:
    f.write(replace_in_mysql(content))
PYEOF
    success "已自动同步 MySQL 8.4 账号密码至配置文件: ${file}"
}

save_and_print_credentials() {
    local connect_host="${MYSQL_BIND_HOST}"
    if [[ "${connect_host}" == "0.0.0.0" ]]; then
        connect_host="127.0.0.1"
    fi

    cat > "${CREDENTIAL_FILE}" <<EOF
# MySQL 8.4 LTS 自动部署凭据记录
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
DEPLOY_MODE="${ACTIVE_MODE}"
MYSQL_VERSION="8.4 LTS"
MYSQL_HOST="${connect_host}"
MYSQL_PORT="${MYSQL_PORT}"
MYSQL_DATABASE="${MYSQL_DATABASE}"
MYSQL_ROOT_USER="${MYSQL_ROOT_USER}"
MYSQL_ROOT_PASSWORD='${MYSQL_ROOT_PASSWORD}'
MYSQL_APP_USER="${MYSQL_APP_USER}"
MYSQL_APP_PASSWORD='${MYSQL_APP_PASSWORD}'
EOF
    chmod 600 "${CREDENTIAL_FILE}"

    echo -e "\n${GREEN}================================================================================${NC}"
    echo -e "${GREEN}🎉 MySQL 8.4 LTS 一键自动化部署完成！请妥善保存以下账号密码信息：${NC}"
    echo -e "${GREEN}================================================================================${NC}"
    echo -e "  ${BOLD}部署模式:${NC}         ${CYAN}${ACTIVE_MODE} (MySQL 8.4 LTS)${NC}"
    echo -e "  ${BOLD}主机地址:${NC}         ${CYAN}${connect_host}${NC}"
    echo -e "  ${BOLD}监听端口:${NC}         ${CYAN}${MYSQL_PORT}${NC}"
    echo -e "  ${BOLD}默认数据库名:${NC}     ${CYAN}${MYSQL_DATABASE}${NC} (已初始化 utf8mb4 及项目表结构)"
    echo -e "--------------------------------------------------------------------------------"
    echo -e "  ${BOLD}🔑 Root 管理员账号:${NC} ${YELLOW}${MYSQL_ROOT_USER}${NC}"
    echo -e "  ${BOLD}🔑 Root 管理员密码:${NC} ${YELLOW}${MYSQL_ROOT_PASSWORD}${NC}"
    echo -e "--------------------------------------------------------------------------------"
    echo -e "  ${BOLD}👤 业务数据库账号:${NC}  ${GREEN}${MYSQL_APP_USER}${NC}"
    echo -e "  ${BOLD}🔒 业务数据库密码:${NC}  ${GREEN}${MYSQL_APP_PASSWORD}${NC}"
    echo -e "--------------------------------------------------------------------------------"
    echo -e "  ${BOLD}终端连接命令:${NC}"
    echo -e "    mysql -h ${connect_host} -P ${MYSQL_PORT} -u ${MYSQL_APP_USER} -p'${MYSQL_APP_PASSWORD}' ${MYSQL_DATABASE}"
    echo -e "  ${BOLD}Go DSN 连接串:${NC}"
    echo -e "    ${MYSQL_APP_USER}:${MYSQL_APP_PASSWORD}@tcp(${connect_host}:${MYSQL_PORT})/${MYSQL_DATABASE}?charset=utf8mb4&parseTime=true&loc=Local"
    echo -e "  ${BOLD}凭据备份文件:${NC}     ${CYAN}${CREDENTIAL_FILE}${NC} (权限 600，可随时运行 ./deploy_mysql84.sh credentials 查看)"
    echo -e "${GREEN}================================================================================${NC}\n"
}

# ==============================================================================
# 子命令分发执行
# ==============================================================================
case "${COMMAND}" in
    install)
        prompt_interactive
        ensure_passwords
        resolve_deploy_mode

        if [[ "${ACTIVE_MODE}" == "docker" ]]; then
            deploy_mysql_docker
        else
            deploy_mysql_native
        fi

        if [[ "${SYNC_CONFIG}" == "true" ]]; then
            update_yaml_mysql_section "${PROJECT_ROOT}/config.yaml"
            update_yaml_mysql_section "${PROJECT_ROOT}/backend/config.yaml"
            update_yaml_mysql_section "/opt/wallfacer/config.yaml"
        fi

        save_and_print_credentials
        ;;

    credentials|info)
        if [[ ! -f "${CREDENTIAL_FILE}" ]]; then
            error "未找到已保存的凭据文件 (${CREDENTIAL_FILE})，请先执行 ./deploy_mysql84.sh install"
        fi
        # shellcheck disable=SC1090
        source "${CREDENTIAL_FILE}"
        ACTIVE_MODE="${DEPLOY_MODE}"
        MYSQL_BIND_HOST="${MYSQL_HOST}"
        save_and_print_credentials
        ;;

    reset-password)
        if [[ -f "${CREDENTIAL_FILE}" ]]; then
            # shellcheck disable=SC1090
            source "${CREDENTIAL_FILE}"
        fi
        NEW_ROOT_PASS="${MYSQL_ROOT_PASSWORD}"
        NEW_APP_PASS="$(generate_strong_password)"
        MYSQL_APP_PASSWORD="${NEW_APP_PASS}"
        ACTIVE_MODE="${DEPLOY_MODE:-docker}"

        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}$"; then
            docker exec -i "${CONTAINER_NAME}" mysql -uroot -p"${NEW_ROOT_PASS}" -e "
                ALTER USER '${MYSQL_APP_USER}'@'localhost' IDENTIFIED BY '${NEW_APP_PASS}';
                ALTER USER '${MYSQL_APP_USER}'@'%' IDENTIFIED BY '${NEW_APP_PASS}';
                FLUSH PRIVILEGES;
            "
            ACTIVE_MODE="docker"
        else
            mysql -uroot -p"${NEW_ROOT_PASS}" -e "
                ALTER USER '${MYSQL_APP_USER}'@'localhost' IDENTIFIED BY '${NEW_APP_PASS}';
                ALTER USER '${MYSQL_APP_USER}'@'127.0.0.1' IDENTIFIED BY '${NEW_APP_PASS}';
                FLUSH PRIVILEGES;
            "
            ACTIVE_MODE="native"
        fi

        if [[ "${SYNC_CONFIG}" == "true" ]]; then
            update_yaml_mysql_section "${PROJECT_ROOT}/config.yaml"
            update_yaml_mysql_section "${PROJECT_ROOT}/backend/config.yaml"
            update_yaml_mysql_section "/opt/wallfacer/config.yaml"
        fi
        save_and_print_credentials
        ;;

    status)
        if command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
            docker ps -f "name=^/${CONTAINER_NAME}$"
        elif command -v systemctl >/dev/null 2>&1; then
            systemctl status mysqld mysql --no-pager 2>/dev/null || warn "未检测到运行中的 systemd MySQL 服务"
        else
            pgrep -fl mysqld || warn "未检测到运行中的 MySQL 进程"
        fi
        ;;

    restart)
        if command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
            docker restart "${CONTAINER_NAME}"
            success "Docker 容器 [${CONTAINER_NAME}] 已重启"
        elif command -v systemctl >/dev/null 2>&1; then
            systemctl restart mysqld 2>/dev/null || systemctl restart mysql
            success "systemd MySQL 服务已重启"
        fi
        ;;

    stop)
        if command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
            docker stop "${CONTAINER_NAME}"
            success "Docker 容器 [${CONTAINER_NAME}] 已停止"
        elif command -v systemctl >/dev/null 2>&1; then
            systemctl stop mysqld 2>/dev/null || systemctl stop mysql
            success "systemd MySQL 服务已停止"
        fi
        ;;

    logs)
        if command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
            docker logs -f --tail 100 "${CONTAINER_NAME}"
        elif [[ -f /var/log/mysqld.log ]]; then
            tail -f -n 100 /var/log/mysqld.log
        elif [[ -f /var/log/mysql/error.log ]]; then
            tail -f -n 100 /var/log/mysql/error.log
        else
            journalctl -u mysqld -u mysql -f -n 100
        fi
        ;;

    uninstall)
        if command -v docker >/dev/null 2>&1 && docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
            info "正在停止并移除 Docker 容器 ${CONTAINER_NAME}..."
            docker rm -f "${CONTAINER_NAME}"
            success "MySQL 8.4 容器已移除（数据目录 ${MYSQL_DATA_DIR} 已保留，如需彻底清空请执行: sudo rm -rf ${MYSQL_DATA_DIR}）"
        elif command -v systemctl >/dev/null 2>&1; then
            systemctl stop mysqld mysql 2>/dev/null || true
            systemctl disable mysqld mysql 2>/dev/null || true
            success "MySQL 系统服务已停止并取消开机自启"
        fi
        ;;
esac

