#!/usr/bin/env bash
# ==============================================================================
# 面壁者转发 (Wallfacer Forwarder) - 一键编译与部署脚本
# 支持系统: Linux (Ubuntu / Debian / CentOS / Rocky / Alpine 等) & macOS
# 支持功能:
#   1. 自动编译 Vue 3 前端静态产物 (frontend/dist) 与 Go 静态二进制文件
#   2. 交互式或静默参数化生成 config.yaml（自动生成 UUID 作为 jwt_secret、自定义 MySQL 库名）
#   3. Linux 自动开启内核转发 (net.ipv4.ip_forward=1)
#   4. 自动注册并启动 systemd 常驻服务 (wallfacer.service)
#   5. 可选一键生成 Nginx 反向代理与静态托管配置
#   6. 支持 install / build / update / unlock / status / logs / uninstall 子命令
# ==============================================================================

set -euo pipefail

# 恢复用户完整 Shell 环境变量（解决 sudo 強制重置 PATH 为 /sbin:/bin:/usr/sbin:/usr/bin
# 或覆盖 nvm / 宝塔 / 自定义 Node.js 与 Go 路径，导致调到系统旧版 /usr/bin/node 报错的问题）
load_user_env() {
    set +eu
    local real_home="${HOME:-/root}"
    if [[ -n "${SUDO_USER:-}" ]] && [[ "${SUDO_USER}" != "root" ]]; then
        real_home="$(eval echo "~${SUDO_USER}" 2>/dev/null || echo "/root")"
    fi
    [[ -f /etc/profile ]] && source /etc/profile >/dev/null 2>&1
    [[ -f "${real_home}/.bash_profile" ]] && source "${real_home}/.bash_profile" >/dev/null 2>&1
    [[ -f "${real_home}/.bashrc" ]] && source "${real_home}/.bashrc" >/dev/null 2>&1
    [[ -f /root/.bash_profile ]] && source /root/.bash_profile >/dev/null 2>&1
    [[ -f /root/.bashrc ]] && source /root/.bashrc >/dev/null 2>&1

    export NVM_DIR="${NVM_DIR:-/root/.nvm}"
    [[ -s "${NVM_DIR}/nvm.sh" ]] && source "${NVM_DIR}/nvm.sh" >/dev/null 2>&1

    # 自动探测 nvm / 宝塔 / 常见高版本 Node.js 目录并置于 PATH 最前，防止被 /usr/bin 或 /usr/local/bin 下的旧版 node 抢占
    local node_dirs=()
    for d in /root/.nvm/versions/node/*/bin "${real_home}"/.nvm/versions/node/*/bin /www/server/nodejs/*/bin /www/server/nvm/versions/node/*/bin /usr/local/node*/bin; do
        if [[ -x "${d}/node" ]]; then
            node_dirs+=("${d}")
        fi
    done
    if [[ ${#node_dirs[@]} -gt 0 ]]; then
        local latest_node_bin
        latest_node_bin="$(printf '%s\n' "${node_dirs[@]}" | sort -V | tail -n 1)"
        export PATH="${latest_node_bin}:${PATH}"
    fi

    # 将 Go 常见安装路径追加到 PATH 末尾（绝不把 /usr/local/bin 放到 PATH 最前面覆盖用户环境）
    export PATH="${PATH}:/usr/local/go/bin:/www/server/go/bin:/root/go/bin:/opt/homebrew/bin"
    set -eu
}
load_user_env

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${PROJECT_ROOT}/backend"
FRONTEND_DIR="${PROJECT_ROOT}/frontend"
DEPLOY_ENV_FILE="${PROJECT_ROOT}/.deploy_env"

CLI_DIR_SET="false"
CLI_PORT_SET="false"
CLI_DB_HOST_SET="false"
CLI_DB_PORT_SET="false"
CLI_DB_USER_SET="false"
CLI_DB_PASS_SET="false"
CLI_DB_NAME_SET="false"
CLI_ADMIN_USER_SET="false"
CLI_ADMIN_PASS_SET="false"
SAVED_JWT_SECRET=""

# 若已记录过上次部署状态，读取作为初始候选值
if [[ -f "${DEPLOY_ENV_FILE}" ]]; then
    # shellcheck disable=SC1090
    source "${DEPLOY_ENV_FILE}"
    if [[ -n "${SAVED_INSTALL_DIR:-}" ]]; then
        INSTALL_DIR="${INSTALL_DIR:-${SAVED_INSTALL_DIR}}"
    fi
fi

# 若已执行过 deploy_mysql84.sh，自动加载其生成的 MySQL 8.4 凭据作为默认值
if [[ -f "${PROJECT_ROOT}/.mysql84_credentials" ]]; then
    # shellcheck disable=SC1091
    source "${PROJECT_ROOT}/.mysql84_credentials"
    MYSQL_USER="${MYSQL_USER:-${MYSQL_APP_USER:-root}}"
    MYSQL_PASSWORD="${MYSQL_PASSWORD:-${MYSQL_APP_PASSWORD:-your_mysql_password}}"
fi

# 默认部署参数（可通过环境变量或命令行参数覆盖）
INSTALL_DIR="${INSTALL_DIR:-/opt/wallfacer}"
SERVICE_NAME="${SERVICE_NAME:-wallfacer}"
SERVER_HOST="${SERVER_HOST:-0.0.0.0}"
SERVER_PORT="${SERVER_PORT:-8080}"
MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-your_mysql_password}"
MYSQL_DATABASE="${MYSQL_DATABASE:-wallfacer_forwarder}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Admin@2026!}"
DNS_INTERVAL="${DNS_INTERVAL:-60}"
NGINX_DOMAIN="${NGINX_DOMAIN:-}"
WITH_MYSQL84="${WITH_MYSQL84:-false}"
NON_INTERACTIVE="${NON_INTERACTIVE:-false}"

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*" >&2; exit 1; }

# 生成随机 UUID v4 (用于 jwt_secret)
generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    elif [[ -r /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    elif command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 16 | sed -E 's/^(.{8})(.{4})(.{4})(.{4})(.{12})$/\1-\2-\3-\4-\5/'
    else
        date +%s%N | sha256sum | head -c 36
    fi
}

# 检测系统与架构
detect_platform() {
    OS_TYPE="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH_RAW="$(uname -m)"
    case "${ARCH_RAW}" in
        x86_64|amd64) ARCH_TYPE="amd64" ;;
        aarch64|arm64) ARCH_TYPE="arm64" ;;
        *) error "暂不支持的 CPU 架构: ${ARCH_RAW}" ;;
    esac
    info "检测到当前系统平台: ${OS_TYPE}/${ARCH_TYPE}"
}

# 打印帮助信息
usage() {
    cat <<EOF
用法: $(basename "$0") [命令] [选项]

可用命令:
  install       一键编译、安装、配置并启动服务（默认命令）
  build         仅编译前端静态文件 (frontend/dist) 与后端二进制文件
  build-linux   交叉编译 Linux (amd64 & arm64) 生产二进制与前端静态包
  update        保留现有 config.yaml 配置，重新编译更新程序并重启服务
  unlock        重启后端服务，立即清零等保三级登录失败锁定状态
  restart       重启服务
  stop          停止服务
  status        查看服务运行状态
  logs          实时查看服务日志
  uninstall     停止并卸载系统服务

可选参数 (用于 install 命令):
  -y, --yes                   非交互静默安装（使用默认值或已传入的参数）
  --dir <path>                安装目录 (默认: /opt/wallfacer)
  --port <port>               后端监听端口 (默认: 8080)
  --db-host <host>            MySQL 主机地址 (默认: 127.0.0.1)
  --db-port <port>            MySQL 端口 (默认: 3306)
  --db-user <user>            MySQL 用户名 (默认: root)
  --db-pass <password>        MySQL 密码
  --db-name <database>        自定义 MySQL 数据库名 (默认: wallfacer_forwarder)
  --admin-user <username>     初始管理员账号 (默认: admin)
  --admin-pass <password>     初始管理员密码 (默认: Admin@2026!，需满足等保三级强口令)
  --nginx-domain <domain/ip>  自动生成 Nginx 站点配置并指向该域名或服务器 IP
  --with-mysql84              部署前自动调用 deploy_mysql84.sh 一键部署 MySQL 8.4 LTS
  -h, --help                  显示此帮助说明

示例:
  # 1. 交互式一键部署（推荐）
  sudo ./deploy.sh

  # 2. 静默参数化一键部署（自定义数据库名与端口）
  sudo ./deploy.sh install -y \\
    --port 8080 \\
    --db-host 127.0.0.1 --db-port 3306 \\
    --db-user root --db-pass 'MyRootPwd@123' \\
    --db-name 'my_custom_forwarder'

  # 3. 仅在本地交叉编译打包 Linux 部署产物
  ./deploy.sh build-linux
EOF
}

# 解析命令行参数
COMMAND="install"
if [[ $# -gt 0 ]]; then
    case "$1" in
        install|build|build-linux|update|unlock|restart|stop|status|logs|uninstall)
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
        --dir)              INSTALL_DIR="$2"; CLI_DIR_SET="true"; shift 2 ;;
        --port)             SERVER_PORT="$2"; CLI_PORT_SET="true"; shift 2 ;;
        --db-host)          MYSQL_HOST="$2"; CLI_DB_HOST_SET="true"; shift 2 ;;
        --db-port)          MYSQL_PORT="$2"; CLI_DB_PORT_SET="true"; shift 2 ;;
        --db-user)          MYSQL_USER="$2"; CLI_DB_USER_SET="true"; shift 2 ;;
        --db-pass)          MYSQL_PASSWORD="$2"; CLI_DB_PASS_SET="true"; shift 2 ;;
        --db-name)          MYSQL_DATABASE="$2"; CLI_DB_NAME_SET="true"; shift 2 ;;
        --admin-user)       ADMIN_USER="$2"; CLI_ADMIN_USER_SET="true"; shift 2 ;;
        --admin-pass)       ADMIN_PASSWORD="$2"; CLI_ADMIN_PASS_SET="true"; shift 2 ;;
        --nginx-domain)     NGINX_DOMAIN="$2"; shift 2 ;;
        --with-mysql84)     WITH_MYSQL84="true"; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  error "未知参数: $1 (使用 --help 查看帮助)" ;;
    esac
done

# 从 YAML 配置文件中安全提取指定段落的键值（兼容带引号及含 #/@ 等特殊符号的密码）
yaml_get() {
    local file="$1"
    local section="$2"
    local key="$3"
    [[ -f "${file}" ]] || return 0
    awk -v sec="${section}" -v k="${key}" '
        /^[a-zA-Z0-9_]+:[[:space:]]*$/ {
            line = $0
            sub(/:[[:space:]]*$/, "", line)
            cur_sec = line
            next
        }
        cur_sec == sec {
            if (match($0, "^[[:space:]]+" k ":[[:space:]]*")) {
                val = substr($0, RLENGTH + 1)
                if (substr(val, 1, 1) == "\"") {
                    sub(/^"/, "", val)
                    sub(/"[[:space:]]*$/, "", val)
                } else if (substr(val, 1, 1) == "\x27") {
                    sub(/^\x27/, "", val)
                    sub(/\x27[[:space:]]*$/, "", val)
                } else {
                    sub(/[[:space:]]+#.*$/, "", val)
                    sub(/[[:space:]]+$/, "", val)
                }
                print val
                exit
            }
        }
    ' "${file}"
}

# 解析指定 config.yaml 中的服务配置与 MySQL 配置
load_config_from_yaml() {
    local cfg_file="$1"
    [[ -f "${cfg_file}" ]] || return 0

    local v_host v_port v_jwt v_db_host v_db_port v_db_user v_db_pass v_db_name v_adm_user v_adm_pass v_dns_int
    v_host="$(yaml_get "${cfg_file}" "server" "host")"
    v_port="$(yaml_get "${cfg_file}" "server" "port")"
    v_jwt="$(yaml_get "${cfg_file}" "server" "jwt_secret")"
    v_db_host="$(yaml_get "${cfg_file}" "mysql" "host")"
    v_db_port="$(yaml_get "${cfg_file}" "mysql" "port")"
    v_db_user="$(yaml_get "${cfg_file}" "mysql" "user")"
    v_db_pass="$(yaml_get "${cfg_file}" "mysql" "password")"
    v_db_name="$(yaml_get "${cfg_file}" "mysql" "database")"
    v_adm_user="$(yaml_get "${cfg_file}" "auth" "initial_admin_user")"
    v_adm_pass="$(yaml_get "${cfg_file}" "auth" "initial_admin_password")"
    v_dns_int="$(yaml_get "${cfg_file}" "dns_watcher" "interval_seconds")"

    [[ -n "${v_host}" ]] && SERVER_HOST="${v_host}"
    [[ "${CLI_PORT_SET}" != "true" && -n "${v_port}" ]] && SERVER_PORT="${v_port}"
    [[ -n "${v_jwt}" ]] && SAVED_JWT_SECRET="${v_jwt}"
    [[ "${CLI_DB_HOST_SET}" != "true" && -n "${v_db_host}" ]] && MYSQL_HOST="${v_db_host}"
    [[ "${CLI_DB_PORT_SET}" != "true" && -n "${v_db_port}" ]] && MYSQL_PORT="${v_db_port}"
    [[ "${CLI_DB_USER_SET}" != "true" && -n "${v_db_user}" ]] && MYSQL_USER="${v_db_user}"
    [[ "${CLI_DB_PASS_SET}" != "true" && -n "${v_db_pass}" ]] && MYSQL_PASSWORD="${v_db_pass}"
    [[ "${CLI_DB_NAME_SET}" != "true" && -n "${v_db_name}" ]] && MYSQL_DATABASE="${v_db_name}"
    [[ "${CLI_ADMIN_USER_SET}" != "true" && -n "${v_adm_user}" ]] && ADMIN_USER="${v_adm_user}"
    [[ "${CLI_ADMIN_PASS_SET}" != "true" && -n "${v_adm_pass}" ]] && ADMIN_PASSWORD="${v_adm_pass}"
    [[ -n "${v_dns_int}" ]] && DNS_INTERVAL="${v_dns_int}"

    info "已从现有配置 (${cfg_file}) 读取 MySQL 配置: ${MYSQL_USER}@${MYSQL_HOST}:${MYSQL_PORT}/${MYSQL_DATABASE} (监听端口: ${SERVER_PORT})"
}

# 根据正在运行的 wallfacer-backend 进程 (/proc/<pid>/exe、cwd、environ) 及 systemd 服务自动探测上次启动路径与 MySQL 配置
inspect_running_process_and_config() {
    local pid=""
    local proc_cfg=""
    local proc_dir=""

    # 1. 优先通过 systemd MainPID 或 pgrep 查找正在运行的 wallfacer-backend 进程
    if command -v systemctl >/dev/null 2>&1; then
        pid="$(systemctl show -p MainPID --value "${SERVICE_NAME}" 2>/dev/null || true)"
        [[ "${pid}" == "0" ]] && pid=""
    fi
    if [[ -z "${pid}" ]] && command -v pgrep >/dev/null 2>&1; then
        pid="$(pgrep -f "wallfacer-backend" 2>/dev/null | head -n 1 || true)"
    fi

    if [[ -n "${pid}" ]]; then
        if [[ -d "/proc/${pid}" ]]; then
            # Linux: 从 /proc/<pid>/environ、exe、cwd 精确读取进程启动路径和 CONFIG_PATH
            proc_cfg="$(tr '\0' '\n' < "/proc/${pid}/environ" 2>/dev/null | awk -F= '/^CONFIG_PATH=/{print substr($0, 13); exit}' || true)"
            local proc_exe proc_cwd
            proc_exe="$(readlink -f "/proc/${pid}/exe" 2>/dev/null | sed 's/ (deleted)$//' || true)"
            proc_cwd="$(readlink -f "/proc/${pid}/cwd" 2>/dev/null || true)"

            if [[ -n "${proc_cfg}" ]] && [[ -f "${proc_cfg}" ]]; then
                proc_dir="$(dirname "${proc_cfg}")"
            elif [[ -n "${proc_exe}" ]] && [[ -f "$(dirname "${proc_exe}")/config.yaml" ]]; then
                proc_dir="$(dirname "${proc_exe}")"
                proc_cfg="${proc_dir}/config.yaml"
            elif [[ -n "${proc_cwd}" ]] && [[ -f "${proc_cwd}/config.yaml" ]]; then
                proc_dir="${proc_cwd}"
                proc_cfg="${proc_cwd}/config.yaml"
            elif [[ -n "${proc_exe}" ]] && [[ "$(dirname "${proc_exe}")" != "${BACKEND_DIR}" ]]; then
                proc_dir="$(dirname "${proc_exe}")"
            fi
        else
            # macOS / BSD: 通过 ps 与 lsof 获取进程路径
            local cmd_bin
            cmd_bin="$(ps -p "${pid}" -o comm= 2>/dev/null | awk '{print $1}' || true)"
            if [[ -n "${cmd_bin}" ]] && [[ "${cmd_bin}" == /* ]] && [[ "$(dirname "${cmd_bin}")" != "${BACKEND_DIR}" ]]; then
                proc_dir="$(dirname "${cmd_bin}")"
                [[ -f "${proc_dir}/config.yaml" ]] && proc_cfg="${proc_dir}/config.yaml"
            fi
        fi

        if [[ -n "${proc_dir}" ]] && [[ "${CLI_DIR_SET}" != "true" ]]; then
            INSTALL_DIR="${proc_dir}"
            info "已通过运行中进程 (PID: ${pid}) 自动定位上次启动路径: ${INSTALL_DIR}"
        fi
    fi

    # 2. 若进程当前未运行，从 systemd 服务单元配置 (CONFIG_PATH / WorkingDirectory / ExecStart) 提取上次启动路径
    if [[ -z "${proc_dir}" ]] && [[ "${CLI_DIR_SET}" != "true" ]]; then
        local svc_file="/etc/systemd/system/${SERVICE_NAME}.service"
        if [[ -f "${svc_file}" ]]; then
            local svc_cfg svc_wd svc_exec
            svc_cfg="$(sed -n 's/.*CONFIG_PATH=\([^" ]*\).*/\1/p' "${svc_file}" | head -n 1 || true)"
            svc_wd="$(awk -F= '/^WorkingDirectory=/{print $2; exit}' "${svc_file}" | tr -d '[:space:]' || true)"
            svc_exec="$(awk -F= '/^ExecStart=/{print $2; exit}' "${svc_file}" | awk '{print $1}' || true)"

            if [[ -n "${svc_cfg}" ]] && [[ -f "${svc_cfg}" ]]; then
                INSTALL_DIR="$(dirname "${svc_cfg}")"
                proc_cfg="${svc_cfg}"
            elif [[ -n "${svc_wd}" ]] && [[ -d "${svc_wd}" ]]; then
                INSTALL_DIR="${svc_wd}"
                [[ -f "${svc_wd}/config.yaml" ]] && proc_cfg="${svc_wd}/config.yaml"
            elif [[ -n "${svc_exec}" ]]; then
                INSTALL_DIR="$(dirname "${svc_exec}")"
            fi
            info "已从 systemd 服务单元识别上次启动路径: ${INSTALL_DIR}"
        fi
    fi

    # 3. 自动加载对应路径下 config.yaml 中的 MySQL 配置与服务端口信息
    if [[ -z "${proc_cfg}" ]] && [[ -f "${INSTALL_DIR}/config.yaml" ]]; then
        proc_cfg="${INSTALL_DIR}/config.yaml"
    fi
    if [[ -n "${proc_cfg}" ]] && [[ -f "${proc_cfg}" ]]; then
        load_config_from_yaml "${proc_cfg}"
    fi
}

save_deploy_env() {
    cat > "${DEPLOY_ENV_FILE}" <<EOF
SAVED_INSTALL_DIR="${INSTALL_DIR}"
EOF
    chmod 600 "${DEPLOY_ENV_FILE}" 2>/dev/null || true
}

# 编译前端 Vue 3 工程
build_frontend() {
    if [[ -d "${FRONTEND_DIR}" ]] && command -v npm >/dev/null 2>&1; then
        info "正在编译 Vue 3 前端静态资源 (Node: $(command -v node) $(node -v 2>/dev/null || true))..."
        if (
            cd "${FRONTEND_DIR}"
            if [[ ! -d "node_modules" ]]; then
                npm install --no-audit --no-fund
            fi
            npm run build
        ); then
            success "前端静态资源编译完成: ${FRONTEND_DIR}/dist"
            return 0
        elif [[ -f "${FRONTEND_DIR}/dist/index.html" ]]; then
            warn "前端重新编译未通过，自动复用已有的编译产物: ${FRONTEND_DIR}/dist"
            return 0
        fi
    fi

    if [[ -f "${FRONTEND_DIR}/dist/index.html" ]]; then
        info "直接复用已有的前端编译产物: ${FRONTEND_DIR}/dist"
    else
        warn "未检测到可用的前端编译产物 frontend/dist"
    fi
}

# 自动安装 Go 编译环境（当未找到预编译二进制且系统未安装 Go 时触发）
auto_install_go() {
    if command -v go >/dev/null 2>&1; then
        return 0
    fi
    info "当前系统未检测到 Go 编译器，正在为您自动安装 Go 1.22 环境..."
    local go_tar="go1.22.8.${OS_TYPE}-${ARCH_TYPE}.tar.gz"
    local dl_urls=(
        "https://golang.google.cn/dl/${go_tar}"
        "https://mirrors.aliyun.com/golang/${go_tar}"
        "https://go.dev/dl/${go_tar}"
    )
    local tmp_tar="/tmp/${go_tar}"
    for url in "${dl_urls[@]}"; do
        if curl -fsSL --connect-timeout 10 -m 120 "${url}" -o "${tmp_tar}" 2>/dev/null || wget -q --timeout=15 "${url}" -O "${tmp_tar}" 2>/dev/null; then
            if [[ -s "${tmp_tar}" ]]; then
                rm -rf /usr/local/go
                tar -C /usr/local -xzf "${tmp_tar}"
                rm -f "${tmp_tar}"
                export PATH="/usr/local/go/bin:${PATH}"
                if command -v go >/dev/null 2>&1; then
                    success "已自动安装 Go 环境: $(go version)"
                    return 0
                fi
            fi
        fi
    done

    # 若官方二进制包下载失败，回退使用系统包管理器安装
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y golang && return 0
    elif command -v yum >/dev/null 2>&1; then
        yum install -y golang && return 0
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update -y && apt-get install -y golang-go && return 0
    fi
    return 1
}

# 编译后端 Go 二进制文件
build_backend() {
    local target_os="${1:-${OS_TYPE}}"
    local target_arch="${2:-${ARCH_TYPE}}"
    local output_bin="${3:-${BACKEND_DIR}/wallfacer-backend}"
    local prebuilt_bin="${BACKEND_DIR}/wallfacer-backend-${target_os}-${target_arch}"

    # 1. 若未安装 Go 但存在对应架构的预编译二进制，直接复用
    if ! command -v go >/dev/null 2>&1; then
        if [[ -f "${prebuilt_bin}" ]]; then
            if [[ "${prebuilt_bin}" != "${output_bin}" ]]; then
                cp -f "${prebuilt_bin}" "${output_bin}"
            fi
            chmod +x "${output_bin}"
            success "已直接复用预编译 Linux 二进制文件: $(basename "${prebuilt_bin}")"
            return 0
        elif [[ -f "${output_bin}" ]]; then
            chmod +x "${output_bin}"
            success "已直接复用现有二进制文件: ${output_bin}"
            return 0
        else
            auto_install_go || error "自动安装 Go 环境失败，请手动执行 'yum install -y golang' 或 'apt install -y golang-go'"
        fi
    fi

    # 2. 使用 Go 编译（自动配置国内/海外高可用 GOPROXY 加速依赖拉取）
    info "正在编译 Go 后端二进制文件 (${target_os}/${target_arch}, $(go version 2>/dev/null || true))..."
    if (
        cd "${BACKEND_DIR}"
        export GO111MODULE=on
        export GOPROXY="${GOPROXY:-https://goproxy.cn,https://goproxy.io,direct}"
        go mod tidy
        CGO_ENABLED=0 GOOS="${target_os}" GOARCH="${target_arch}" \
            go build -trimpath -ldflags="-s -w" -o "${output_bin}" .
    ); then
        chmod +x "${output_bin}"
        success "Go 后端编译完成: ${output_bin}"
    elif [[ -f "${prebuilt_bin}" ]]; then
        warn "本地 Go 编译未通过，自动回退使用预编译二进制: $(basename "${prebuilt_bin}")"
        if [[ "${prebuilt_bin}" != "${output_bin}" ]]; then
            cp -f "${prebuilt_bin}" "${output_bin}"
        fi
        chmod +x "${output_bin}"
    else
        error "Go 后端编译失败，请检查网络或 Go 版本"
    fi
}

# 交互式收集配置参数
prompt_config() {
    if [[ "${NON_INTERACTIVE}" == "true" ]]; then
        return
    fi
    echo -e "\n${CYAN}================ 面壁者转发 (Wallfacer Forwarder) 部署向导 ================${NC}"
    read -r -p "1. 安装目标目录 [${INSTALL_DIR}]: " input_dir
    INSTALL_DIR="${input_dir:-${INSTALL_DIR}}"

    read -r -p "2. Go 后端监听端口 [${SERVER_PORT}]: " input_port
    SERVER_PORT="${input_port:-${SERVER_PORT}}"

    read -r -p "3. MySQL 主机地址 [${MYSQL_HOST}]: " input_db_host
    MYSQL_HOST="${input_db_host:-${MYSQL_HOST}}"

    read -r -p "4. MySQL 端口 [${MYSQL_PORT}]: " input_db_port
    MYSQL_PORT="${input_db_port:-${MYSQL_PORT}}"

    read -r -p "5. MySQL 用户名 [${MYSQL_USER}]: " input_db_user
    MYSQL_USER="${input_db_user:-${MYSQL_USER}}"

    read -r -s -p "6. MySQL 密码 [留空保持默认]: " input_db_pass
    echo ""
    MYSQL_PASSWORD="${input_db_pass:-${MYSQL_PASSWORD}}"

    read -r -p "7. 自定义 MySQL 数据库名称 [${MYSQL_DATABASE}]: " input_db_name
    MYSQL_DATABASE="${input_db_name:-${MYSQL_DATABASE}}"

    read -r -p "8. 初始管理员账号 [${ADMIN_USER}]: " input_admin_user
    ADMIN_USER="${input_admin_user:-${ADMIN_USER}}"

    read -r -s -p "9. 初始管理员密码 (需8位以上含大小写+数字+符号) [默认 Admin@2026!]: " input_admin_pass
    echo ""
    ADMIN_PASSWORD="${input_admin_pass:-${ADMIN_PASSWORD}}"

    if command -v nginx >/dev/null 2>&1; then
        read -r -p "10. 检测到已安装 Nginx，是否生成反向代理配置？输入域名或服务器IP启用 (直接回车跳过): " input_domain
        NGINX_DOMAIN="${input_domain:-}"
    fi
    echo -e "${CYAN}===========================================================================${NC}\n"
}

# 生成 config.yaml
write_config_file() {
    local cfg_file="$1"
    local jwt_uuid="${SAVED_JWT_SECRET:-$(generate_uuid)}"

    cat > "${cfg_file}" <<EOF
# 面壁者转发 - Go 后端配置文件
# 由 deploy.sh 自动生成于 $(date '+%Y-%m-%d %H:%M:%S')

server:
  host: "${SERVER_HOST}"
  port: ${SERVER_PORT}
  jwt_secret: "${jwt_uuid}"
  jwt_expire_hours: 24

mysql:
  host: "${MYSQL_HOST}"
  port: ${MYSQL_PORT}
  user: "${MYSQL_USER}"
  password: "${MYSQL_PASSWORD}"
  # 支持任意自定义数据库名，程序启动时会自动创建该数据库及所需表结构
  database: "${MYSQL_DATABASE}"
  charset: "utf8mb4"

auth:
  initial_admin_user: "${ADMIN_USER}"
  initial_admin_password: "${ADMIN_PASSWORD}"
  max_failed_attempts: 5
  lockout_minutes: 15
  session_timeout_minutes: 30

dns_watcher:
  interval_seconds: ${DNS_INTERVAL}

iptables:
  auto_enable_ip_forward: true
  chain_prefix: "IPT_FWD"
  dry_run: false
EOF
    chmod 600 "${cfg_file}"
    success "已生成配置文件: ${cfg_file} (jwt_secret 已使用随机 UUID: ${jwt_uuid})"
}

# 开启 Linux 内核 IPv4 转发
enable_linux_ip_forward() {
    if [[ "${OS_TYPE}" != "linux" ]]; then
        return
    fi
    info "正在配置 Linux 内核 IPv4 转发 (net.ipv4.ip_forward=1)..."
    if [[ -w /proc/sys/net/ipv4/ip_forward ]]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward
    fi
    if [[ -d /etc/sysctl.d ]]; then
        echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wallfacer.conf
        sysctl --system >/dev/null 2>&1 || true
    elif [[ -f /etc/sysctl.conf ]]; then
        if ! grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf; then
            echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
        else
            sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
        fi
        sysctl -p >/dev/null 2>&1 || true
    fi
    success "Linux 内核 IPv4 转发已持久化开启"
}

# 配置 systemd 服务 (Linux) 或后台进程 (macOS)
setup_service() {
    if [[ "${OS_TYPE}" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
        local service_file="/etc/systemd/system/${SERVICE_NAME}.service"
        info "正在创建 systemd 服务: ${service_file}..."
        cat > "${service_file}" <<EOF
[Unit]
Description=Wallfacer Forwarder (面壁者转发 Go Backend)
After=network.target mysql.service mariadb.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="CONFIG_PATH=${INSTALL_DIR}/config.yaml"
ExecStart=${INSTALL_DIR}/wallfacer-backend
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1
        systemctl restart "${SERVICE_NAME}"
        success "systemd 服务 [${SERVICE_NAME}] 已启动并设置开机自启"
    else
        info "当前环境非 systemd Linux，正在后台启动 wallfacer-backend..."
        pkill -f "${INSTALL_DIR}/wallfacer-backend" >/dev/null 2>&1 || true
        nohup env CONFIG_PATH="${INSTALL_DIR}/config.yaml" "${INSTALL_DIR}/wallfacer-backend" \
            > "${INSTALL_DIR}/wallfacer.log" 2>&1 &
        sleep 1
        success "后台进程已启动，日志文件: ${INSTALL_DIR}/wallfacer.log"
    fi
}

# 可选配置 Nginx
setup_nginx() {
    if [[ -z "${NGINX_DOMAIN}" ]]; then
        return
    fi
    if ! command -v nginx >/dev/null 2>&1; then
        warn "未检测到 Nginx，跳过 Nginx 配置生成"
        return
    fi

    local nginx_conf="/etc/nginx/conf.d/wallfacer.conf"
    if [[ ! -d /etc/nginx/conf.d ]] && [[ -d /etc/nginx/sites-enabled ]]; then
        nginx_conf="/etc/nginx/sites-enabled/wallfacer.conf"
    fi

    info "正在生成 Nginx 配置文件: ${nginx_conf}..."
    cat > "${nginx_conf}" <<EOF
server {
    listen 80;
    server_name ${NGINX_DOMAIN};

    root ${INSTALL_DIR}/frontend/dist;
    index index.html;

    gzip on;
    gzip_min_length 1k;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/javascript application/json application/javascript application/xml;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location /api/ {
        proxy_pass http://127.0.0.1:${SERVER_PORT}/api/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    location /assets/ {
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }

    location / {
        try_files \$uri \$uri/ /index.html;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }
}
EOF
    if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx >/dev/null 2>&1 || nginx -s reload || true
        success "Nginx 配置已生效: http://${NGINX_DOMAIN}"
    else
        warn "Nginx 配置校验未通过，请手动检查 ${nginx_conf}"
    fi
}

# 执行命令逻辑
detect_platform

case "${COMMAND}" in
    build)
        build_frontend
        build_backend "${OS_TYPE}" "${ARCH_TYPE}" "${BACKEND_DIR}/wallfacer-backend"
        ;;

    build-linux)
        build_frontend
        build_backend "linux" "amd64" "${BACKEND_DIR}/wallfacer-backend-linux-amd64"
        build_backend "linux" "arm64" "${BACKEND_DIR}/wallfacer-backend-linux-arm64"
        success "Linux 双架构二进制 (amd64 / arm64) 与前端 dist 编译完成！"
        ;;

    install)
        if [[ "${OS_TYPE}" == "linux" ]] && [[ "${EUID}" -ne 0 ]]; then
            error "在 Linux 上安装并配置 iptables / systemd 需要 root 权限，请使用: sudo ./deploy.sh"
        fi
        inspect_running_process_and_config
        if [[ "${WITH_MYSQL84}" == "true" ]] && [[ -f "${PROJECT_ROOT}/deploy_mysql84.sh" ]]; then
            info "正在调用 deploy_mysql84.sh 一键部署 MySQL 8.4 LTS..."
            bash "${PROJECT_ROOT}/deploy_mysql84.sh" install -y --db-name "${MYSQL_DATABASE}"
            if [[ -f "${PROJECT_ROOT}/.mysql84_credentials" ]]; then
                # shellcheck disable=SC1091
                source "${PROJECT_ROOT}/.mysql84_credentials"
                MYSQL_USER="${MYSQL_APP_USER}"
                MYSQL_PASSWORD="${MYSQL_APP_PASSWORD}"
            fi
        fi
        prompt_config
        if [[ -n "${NGINX_DOMAIN}" ]] && command -v nginx >/dev/null 2>&1 && [[ "${SERVER_PORT}" == "80" ]]; then
            warn "检测到同时启用了 Nginx (监听 80 端口) 与 --port 80，为避免端口冲突，已将 Go 后端内部端口调整为 8080（由 Nginx 对外监听 80 端口并反向代理）"
            SERVER_PORT="8080"
        fi
        build_frontend
        build_backend "${OS_TYPE}" "${ARCH_TYPE}" "${BACKEND_DIR}/wallfacer-backend"

        info "正在部署文件到 ${INSTALL_DIR}..."
        mkdir -p "${INSTALL_DIR}/frontend"
        cp -f "${BACKEND_DIR}/wallfacer-backend" "${INSTALL_DIR}/wallfacer-backend"
        chmod +x "${INSTALL_DIR}/wallfacer-backend"
        cp -f "${PROJECT_ROOT}/init.sql" "${INSTALL_DIR}/init.sql"

        if [[ -d "${FRONTEND_DIR}/dist" ]]; then
            rm -rf "${INSTALL_DIR}/frontend/dist"
            cp -R "${FRONTEND_DIR}/dist" "${INSTALL_DIR}/frontend/dist"
        fi

        if [[ -f "${INSTALL_DIR}/config.yaml" ]] && [[ "${NON_INTERACTIVE}" != "true" ]]; then
            read -r -p "检测到已存在 ${INSTALL_DIR}/config.yaml，是否覆盖？[y/N]: " overwrite_cfg
            if [[ "${overwrite_cfg}" =~ ^[Yy]$ ]]; then
                write_config_file "${INSTALL_DIR}/config.yaml"
            else
                info "保留现有配置文件: ${INSTALL_DIR}/config.yaml"
            fi
        else
            write_config_file "${INSTALL_DIR}/config.yaml"
        fi

        if command -v mysql >/dev/null 2>&1 && [[ -f "${PROJECT_ROOT}/init.sql" ]]; then
            if mysql -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" \
                -e "CREATE DATABASE IF NOT EXISTS \`${MYSQL_DATABASE}\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" >/dev/null 2>&1; then
                mysql -h "${MYSQL_HOST}" -P "${MYSQL_PORT}" -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" "${MYSQL_DATABASE}" < "${PROJECT_ROOT}/init.sql" >/dev/null 2>&1 || true
                success "已向 MySQL 数据库 [${MYSQL_DATABASE}] 初始化表结构 (init.sql)"
            fi
        fi

        enable_linux_ip_forward
        setup_service
        setup_nginx
        save_deploy_env

        echo -e "\n${GREEN}===========================================================================${NC}"
        echo -e "${GREEN}🎉 面壁者转发 (Wallfacer Forwarder) 一键部署完成！${NC}"
        echo -e "  - 安装目录:     ${CYAN}${INSTALL_DIR}${NC}"
        echo -e "  - 配置文件:     ${CYAN}${INSTALL_DIR}/config.yaml${NC}"
        echo -e "  - 自定义数据库: ${CYAN}${MYSQL_DATABASE}${NC} (程序已自动建库建表，失败时自动回退本地存储)"
        if [[ -n "${NGINX_DOMAIN}" ]]; then
            echo -e "  - 访问地址:     ${CYAN}http://${NGINX_DOMAIN}${NC}"
        else
            echo -e "  - 访问地址:     ${CYAN}http://<服务器IP>:${SERVER_PORT}${NC}"
        fi
        echo -e "  - 管理员账号:   ${CYAN}${ADMIN_USER}${NC}"
        echo -e "  - 管理员密码:   ${CYAN}${ADMIN_PASSWORD}${NC}"
        echo -e "  - MySQL 账号:   ${CYAN}${MYSQL_USER}${NC} (端口 ${MYSQL_HOST}:${MYSQL_PORT})"
        echo -e "  - 重启清零锁定: ${YELLOW}sudo ./deploy.sh unlock${NC} (或 sudo systemctl restart ${SERVICE_NAME})"
        echo -e "${GREEN}===========================================================================${NC}"
        ;;

    update)
        inspect_running_process_and_config
        info "正在执行一键热更新 (目标目录: ${INSTALL_DIR}，完整保留现有配置与 MySQL 连接信息)..."
        cfg_backup=""
        if [[ -f "${INSTALL_DIR}/config.yaml" ]]; then
            cfg_backup="$(mktemp /tmp/wallfacer_cfg_XXXXXX)"
            cp -f "${INSTALL_DIR}/config.yaml" "${cfg_backup}"
            success "已从运行进程关联路径锁定现有配置: ${INSTALL_DIR}/config.yaml"
        else
            warn "在 ${INSTALL_DIR} 下未检测到 config.yaml，将根据已识别的运行参数自动生成配置文件"
        fi
        build_frontend
        build_backend "${OS_TYPE}" "${ARCH_TYPE}" "${BACKEND_DIR}/wallfacer-backend"
        mkdir -p "${INSTALL_DIR}/frontend"
        cp -f "${BACKEND_DIR}/wallfacer-backend" "${INSTALL_DIR}/wallfacer-backend"
        chmod +x "${INSTALL_DIR}/wallfacer-backend"
        if [[ -d "${FRONTEND_DIR}/dist" ]]; then
            rm -rf "${INSTALL_DIR}/frontend/dist"
            cp -R "${FRONTEND_DIR}/dist" "${INSTALL_DIR}/frontend/dist"
        fi
        if [[ -n "${cfg_backup}" ]] && [[ -f "${cfg_backup}" ]]; then
            cp -f "${cfg_backup}" "${INSTALL_DIR}/config.yaml"
            chmod 600 "${INSTALL_DIR}/config.yaml"
            rm -f "${cfg_backup}"
        elif [[ ! -f "${INSTALL_DIR}/config.yaml" ]]; then
            write_config_file "${INSTALL_DIR}/config.yaml"
        fi
        save_deploy_env
        setup_service
        success "程序热更新并重启完成！生效路径: ${INSTALL_DIR}/config.yaml (MySQL: ${MYSQL_USER}@${MYSQL_HOST}:${MYSQL_PORT}/${MYSQL_DATABASE})"
        ;;

    unlock|restart)
        inspect_running_process_and_config
        info "正在重启服务（自动清零所有账号的登录失败锁定状态）..."
        if [[ "${OS_TYPE}" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
            systemctl restart "${SERVICE_NAME}"
        else
            setup_service
        fi
        success "服务已重启，所有登录失败计数与锁定状态已自动清零！"
        ;;

    stop)
        inspect_running_process_and_config
        if [[ "${OS_TYPE}" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
            systemctl stop "${SERVICE_NAME}"
        else
            pkill -f "${INSTALL_DIR}/wallfacer-backend" || true
        fi
        success "服务已停止"
        ;;

    status)
        if [[ "${OS_TYPE}" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
            systemctl status "${SERVICE_NAME}" --no-pager
        else
            pgrep -fl "wallfacer-backend" || warn "服务未运行"
        fi
        ;;

    logs)
        inspect_running_process_and_config
        if [[ "${OS_TYPE}" == "linux" ]] && command -v journalctl >/dev/null 2>&1; then
            journalctl -u "${SERVICE_NAME}" -f -n 100
        elif [[ -f "${INSTALL_DIR}/wallfacer.log" ]]; then
            tail -f -n 100 "${INSTALL_DIR}/wallfacer.log"
        else
            warn "未找到日志文件"
        fi
        ;;

    uninstall)
        info "正在停止并卸载 ${SERVICE_NAME} 服务..."
        if [[ "${OS_TYPE}" == "linux" ]] && command -v systemctl >/dev/null 2>&1; then
            systemctl stop "${SERVICE_NAME}" >/dev/null 2>&1 || true
            systemctl disable "${SERVICE_NAME}" >/dev/null 2>&1 || true
            rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
            systemctl daemon-reload
        else
            pkill -f "${INSTALL_DIR}/wallfacer-backend" >/dev/null 2>&1 || true
        fi
        success "系统服务已移除（安装目录 ${INSTALL_DIR} 与配置文件已保留，如需彻底删除请执行: sudo rm -rf ${INSTALL_DIR}）"
        ;;
esac
