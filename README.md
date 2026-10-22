# 面壁者转发 (Wallfacer Forwarder)

基于 **Go 后端** + **Vue 3 (Vite) 前端** 构建的前后端分离端口与动态域名（DDNS）转发管理系统。支持 **配置文件 DIY 自定义 MySQL 数据库名**、**网络安全等级保护三级（等保 2.0 三级）账号密码全密文身份鉴别**、**Linux / macOS 双平台原生流量与实时速率统计**、**本机网卡 IP 自动回程 SNAT**，以及 **定时 / 手动刷新域名 DNS 解析并用最新 IP 覆盖生效配置**。

---

## 一、核心特性

1. **前后端分离架构（Go + Vue 3）**：
   - **Go 后端（`backend/`）**：采用分层架构（`config` / `model` / `auth` / `database` / `iptables` / `dns` / `handler`），无 CGO 依赖，可一键交叉编译为单文件静态二进制在任意 Linux / macOS 服务器运行。
   - **Vue 3 前端（`frontend/`）**：基于 **Vue 3 (`<script setup>` Composition API) + Vite** 构建，生产环境可编译为纯静态文件（`frontend/dist/`）由 Nginx 托管或由 Go 后端直接托管。
2. **自定义数据库名（配置文件 DIY + 页面连通性测试）**：
   - 数据库连接信息与**自定义数据库名**完全在 [`backend/config.yaml`](./backend/config.yaml) 中 DIY 配置，**不在前端页面暴露任何数据库名、主机、端口或账号信息**。
   - 建表脚本 [`init.sql`](./init.sql) 无硬编码库名，支持导入任意名称的数据库；后端启动时也会自动执行 `CREATE DATABASE IF NOT EXISTS \`<自定义库名>\`` 并迁移表结构。
   - 前端提供 **「测试数据库连接」** 按钮（`POST /api/db/test`），支持在不重启的情况下热加载 `config.yaml` 并测试数据库连通性与响应耗时。
3. **网络安全等级保护三级（GB/T 22239-2019）身份鉴别与解锁机制**：
   - **HTTP 模式下账号与密码全密文防抓包**：采用 `RSA-2048` 挑战-应答机制（每次登录获取一次性防重放 `nonce`），前端将 `{ username, password, nonce, ts }` 整体进行带随机非零填充的 `RSA-PKCS#1 v1.5` 加密，HTTP 抓包与浏览器 F12 均无法看到任何账号或密码明文，且密文单次有效防重放。
   - **强口令与防暴力破解**：强制 8~64 位包含大小写字母、数字、特殊字符；连续登录失败 5 次自动锁定 15 分钟；30 分钟无操作会话自动超时退出。
   - **重启程序自动清零锁定状态**：若管理员因误输密码触发 5 次锁定，**只需重启后端程序**，启动时会自动将所有账号的 `failed_attempts` 与 `locked_until` 清零解锁。
4. **动态域名解析刷新 & 自动覆盖配置**：
   - 支持后台定时检测域名 IP 变化，也支持在页面点击 **「刷新解析」**（全局或单条规则）立即重新解析域名。
   - 每次解析出的最新 IPv4 地址会**自动覆盖规则的生效 IP 配置（`resolved_ip`）**，并立即重写同步底层 `iptables` / 转发引擎规则，同时记录到 `dns_change_logs` 变更日志表。
5. **Linux & macOS 跨平台支持 + 实时上下行网速与累计流量**：
   - **Linux**：自动开启内核转发 `net.ipv4.ip_forward=1`，使用独立自定义链 `IPT_FWD_PREROUTING` / `IPT_FWD_POSTROUTING` / `IPT_FWD_FORWARD`（绝不污染系统原有防火墙、Docker、UFW 规则），通过 `iptables -nvx` 与 `/proc/net/dev` 实时统计每条规则与全局的上下行速率（`↑ B/s`、`↓ B/s`）及累计字节数。
   - **macOS**：内置原生 TCP/UDP 协程转发器与 `netstat -ib` 网卡采样，在 macOS 环境下同样具备真实的端口转发与实时速率统计能力。
   - **本机网卡回程 SNAT**：自动枚举本机活动网卡的 IPv4 地址供选择，直接执行 `-j SNAT --to-source <本机网卡IP>`。

---

## 二、目录结构

```text
iptables-forwarder/
├── deploy.sh                        # 面壁者转发一键编译、安装、更新、解锁与运维脚本
├── deploy_mysql84.sh                # MySQL 8.4 LTS 一键自动化部署脚本（自动生成并输出账号密码）
├── init.sql                         # 支持任意自定义数据库名的 MySQL 初始化建表脚本
├── README.md                        # 项目说明、一键部署、编译、配置与 Nginx 部署文档
├── backend/                         # Go 后端工程
│   ├── go.mod                       # Go 模块定义 (兼容 Go 1.18+)
│   ├── config.yaml                  # 后端主配置文件（DIY 数据库名、端口、鉴权策略等）
│   ├── main.go                      # Go 服务端启动入口
│   ├── wallfacer-backend-linux-amd64 # 预编译 Linux x86_64 静态二进制（支持免环境直接部署）
│   ├── wallfacer-backend-linux-arm64 # 预编译 Linux ARM64 静态二进制（支持免环境直接部署）
│   └── internal/
│       ├── config/config.go         # 配置文件加载与环境变量覆盖
│       ├── model/models.go          # 数据模型与请求结构体定义
│       ├── auth/auth.go             # RSA-2048 挑战应答解密、PBKDF2-SHA256、等保三级口令校验与 JWT
│       ├── database/database.go     # MySQL 自动建库建表、重启清零锁定、连通性测试与本地回退存储
│       ├── iptables/manager.go      # Linux iptables 专用链管理、macOS 原生转发器与实时网速采样
│       ├── dns/watcher.go           # 定时域名解析检测与 IP 覆盖同步器
│       └── handler/server.go        # RESTful API 路由、CORS 跨域与静态资源托管
└── frontend/                        # Vue 3 前端工程 (Vite)
    ├── dist/                        # 预编译前端生产静态资源（开箱即用）
    ├── package.json                 # 前端依赖与脚本
    ├── vite.config.js               # Vite 构建与开发期 /api 反向代理配置
    ├── index.html                   # 页面入口
    └── src/
        ├── main.js                  # Vue 3 挂载入口
        ├── style.css                # 全局暗色主题样式
        ├── App.vue                  # 主界面组件
        ├── api/index.js             # API 请求封装
        └── utils/crypto.js          # 前端 RSA-2048 (BigInt) 加密工具
```

---

## 三、一键部署脚本 (`deploy.sh`) 使用指南（推荐）

项目根目录提供了开箱即用的一键编译与部署脚本 [`deploy.sh`](./deploy.sh)，具备以下自动化能力：
- **自适应环境与免编译兜底**：自动加载系统与用户的 `nvm` / 宝塔 / 自定义 Node.js 与 Go 环境（解决 `sudo` 重置 `PATH` 的问题）；若服务器未安装 Go 或 Node.js，可直接复用仓库内置的预编译产物（`frontend/dist` 与 `wallfacer-backend-linux-amd64/arm64`）或自动安装 Go 环境。
- **基于运行中进程的智能热更新 (`update`)**：执行 `sudo ./deploy.sh update` 时，无需重复传入 `--dir` 或数据库参数，脚本会自动通过当前正在运行的 `wallfacer-backend` 进程（读取 `/proc/<PID>/environ`、`exe`、`cwd` 及 `systemd` 单元）定位上次启动路径，并自动解析继承原 `config.yaml` 中的 MySQL 连接配置、监听端口与 `jwt_secret`。
- **端口冲突自动规避**：若同时传入 `--port 80` 与 `--nginx-domain`，脚本检测到已安装 Nginx 时会自动将 Go 后端内部端口调整为 `8080`，由 Nginx 对外监听 `80` 端口并反向代理至后端。

```bash
chmod +x deploy.sh
```

### 1. 交互式一键安装（按提示输入数据库名、端口、密码等）

```bash
sudo ./deploy.sh
```

### 2. 非交互式静默一键部署（适合自动化脚本 / 批量装机）

```bash
sudo ./deploy.sh install -y \
  --dir /opt/wallfacer \
  --port 8080 \
  --db-host 127.0.0.1 \
  --db-port 3306 \
  --db-user root \
  --db-pass 'YourMySQLPassword' \
  --db-name 'wallfacer_forwarder' \
  --admin-user admin \
  --admin-pass 'Admin@2026!' \
  --nginx-domain forwarder.example.com
```

> 若暂不配置 Nginx，省略 `--nginx-domain` 参数即可，Go 后端会自动托管编译好的前端页面，直接通过 `http://<服务器IP>:8080` 访问。

### 3. `deploy.sh` 常用运维子命令

```bash
# 查看所有支持的参数说明
./deploy.sh --help

# 在开发机一键交叉编译 Linux (amd64 + arm64) 二进制文件与前端 dist 静态目录
./deploy.sh build-linux

# 智能热更新：自动从运行中进程识别上次安装路径与 MySQL 配置，保留现有 config.yaml 编译更新并重启服务
sudo ./deploy.sh update

# 密码连续输错 5 次被锁定时，一键重启服务立即清零锁定状态
sudo ./deploy.sh unlock

# 查看服务运行状态 / 实时日志 / 重启 / 停止 / 卸载
sudo ./deploy.sh status
sudo ./deploy.sh logs
sudo ./deploy.sh restart
sudo ./deploy.sh stop
sudo ./deploy.sh uninstall
```

### 4. MySQL 8.4 LTS 一键自动化部署脚本 (`deploy_mysql84.sh`)

若服务器尚未安装 MySQL，可使用配套的 [`deploy_mysql84.sh`](./deploy_mysql84.sh) 一键部署 **MySQL 8.4 LTS**（支持 **Linux 原生系统安装** 与 **Docker 容器化安装** 两种模式），自动初始化数据库与 [`init.sql`](./init.sql) 表结构、自动将账号密码同步至 `config.yaml`，并在**部署完成时高亮输出 Root 账号密码与业务账号密码**：

```bash
chmod +x deploy_mysql84.sh

# 1. 全自动一键部署 MySQL 8.4 LTS（自动生成 16 位强随机密码，完成后直接输出账号密码）
sudo ./deploy_mysql84.sh -y

# 2. 指定 Docker 模式一键部署 MySQL 8.4 LTS
sudo ./deploy_mysql84.sh install -y --mode docker

# 3. 自定义数据库名、用户名与密码一键部署
sudo ./deploy_mysql84.sh install -y \
  --db-name wallfacer_forwarder \
  --db-user wallfacer \
  --db-pass 'Wallfacer@2026!'

# 4. 随时重新查看部署生成的 MySQL 8.4 账号与密码
./deploy_mysql84.sh credentials

# 5. 一键重置业务账号密码并输出新密码
sudo ./deploy_mysql84.sh reset-password

# 6. 查看状态 / 日志 / 重启 / 停止 / 卸载
sudo ./deploy_mysql84.sh status
sudo ./deploy_mysql84.sh logs
sudo ./deploy_mysql84.sh restart
sudo ./deploy_mysql84.sh stop
sudo ./deploy_mysql84.sh uninstall

# 7. 也可在执行 deploy.sh 时附加 --with-mysql84 参数，连同 MySQL 8.4 与转发服务一次性全套部署
sudo ./deploy.sh install -y --with-mysql84
```

---

## 四、配置文件详解 (`backend/config.yaml`)

所有后端配置及数据库自定义参数均在 [`backend/config.yaml`](./backend/config.yaml) 中修改：

```yaml
# 面壁者转发 - Go 后端配置文件

server:
  host: "0.0.0.0"                                    # 后端监听地址（建议生产环境配合 Nginx 使用 127.0.0.1 或 0.0.0.0）
  port: 8080                                         # 后端监听端口
  jwt_secret: "f47ac10b-58cc-4372-a567-0e02b2c3d479" # JWT 签名密钥（支持直接填写 UUID v4 或任意随机长字符串）
  jwt_expire_hours: 24                               # 登录凭证最大有效期（小时）

mysql:
  host: "127.0.0.1"                                  # MySQL 主机地址
  port: 3306                                         # MySQL 端口
  user: "root"                                       # MySQL 用户名
  password: "your_mysql_password"                    # MySQL 密码
  # 自定义数据库名（仅允许字母、数字、下划线、中划线，1~64 位）
  # 程序启动或点击页面「测试数据库连接」时，会自动创建该数据库及所需表结构
  database: "wallfacer_forwarder"
  charset: "utf8mb4"

auth:
  initial_admin_user: "admin"                        # 首次初始化时的默认管理员账号
  initial_admin_password: "Admin@2026!"              # 首次初始化时的默认管理员密码（需满足等保三级复杂度）
  max_failed_attempts: 5                             # 连续登录失败触发锁定的次数
  lockout_minutes: 15                                # 触发防爆破后的锁定时长（分钟），重启程序可立即清零解锁
  session_timeout_minutes: 30                        # 页面无操作自动退出的闲置超时时间（分钟）

dns_watcher:
  interval_seconds: 60                               # 后台定时解析域名的默认周期（秒），支持在 Web 页面动态调整

iptables:
  auto_enable_ip_forward: true                       # 启动时自动执行 sysctl -w net.ipv4.ip_forward=1 开启内核转发
  chain_prefix: "IPT_FWD"                            # 自定义 iptables 链前缀（生成 IPT_FWD_PREROUTING 等独立链）
  dry_run: false                                     # 设为 true 时仅生成命令不实际执行（非 Linux 环境自动使用内置转发器）
```

> **环境变量覆盖支持**：
> 除直接编辑 `config.yaml` 外，还支持通过环境变量覆盖对应配置：
> `CONFIG_PATH`（指定配置文件路径）、`SERVER_HOST`、`SERVER_PORT`、`MYSQL_HOST`、`MYSQL_PORT`、`MYSQL_USER`、`MYSQL_PASSWORD`、`MYSQL_DATABASE`。

---

## 五、MySQL 数据库初始化（支持自定义数据库名）

### 方式 1：程序自动建库建表（推荐）
只需在 `backend/config.yaml` 中将 `mysql.database` 修改为你想要的任意数据库名（例如 `my_forwarder_db`），启动 Go 后端（或在页面点击 **「测试数据库连接」**）时，程序会自动执行 `CREATE DATABASE IF NOT EXISTS \`my_forwarder_db\`` 并创建所有表结构与初始管理员账号。

### 方式 2：使用 `init.sql` 手动导入自定义数据库名
[`init.sql`](./init.sql) 已去除硬编码库名，可通过命令行指定任意数据库名导入：

```bash
# 1. 创建你自定义名称的数据库（将 custom_db_name 替换为你的库名）
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS custom_db_name DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"

# 2. 将表结构导入该自定义数据库
mysql -u root -p custom_db_name < init.sql
```

---

## 六、手动编译 Go 后端二进制文件的方法

如果不使用 `deploy.sh`，也可以手动编译。进入 `backend` 目录并拉取依赖：

```bash
cd backend
go mod tidy
```

### 1. 本机直接编译（生成当前系统可执行二进制）

```bash
# 使用 -ldflags="-s -w" 去除符号表和调试信息，大幅减小二进制体积
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o wallfacer-backend .
```

### 2. 跨平台交叉编译（例如在 macOS 上编译 Linux 服务器二进制）

- **编译为 Linux x86_64 (amd64) 二进制文件**（最常用云服务器架构）：
  ```bash
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o wallfacer-backend-linux-amd64 .
  ```

- **编译为 Linux ARM64 (aarch64) 二进制文件**（ARM 云服务器 / 树莓派 / 软路由）：
  ```bash
  CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o wallfacer-backend-linux-arm64 .
  ```

- **编译为 macOS Apple Silicon (arm64) 二进制文件**：
  ```bash
  CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o wallfacer-backend-darwin-arm64 .
  ```

- **编译为 macOS Intel (amd64) 二进制文件**：
  ```bash
  CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o wallfacer-backend-darwin-amd64 .
  ```

### 3. 手动配置 Systemd 常驻服务

在 Linux 服务器上，由于操作 `iptables` 与 `sysctl` 需要 `root` 权限，可将编译好的二进制文件与 `config.yaml` 放置于 `/opt/wallfacer/` 目录并通过 `systemd` 管理：

```bash
sudo mkdir -p /opt/wallfacer
sudo cp wallfacer-backend-linux-amd64 /opt/wallfacer/wallfacer-backend
sudo cp config.yaml /opt/wallfacer/config.yaml
sudo chmod +x /opt/wallfacer/wallfacer-backend
```

创建 `/etc/systemd/system/wallfacer.service`：

```ini
[Unit]
Description=Wallfacer Forwarder (面壁者转发 Go Backend)
After=network.target mysql.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/wallfacer
Environment="CONFIG_PATH=/opt/wallfacer/config.yaml"
ExecStart=/opt/wallfacer/wallfacer-backend
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

启动并设置开机自启：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wallfacer
sudo systemctl status wallfacer
```

> **如何解除登录失败 5 次锁定？**
> 直接重启服务即可立即将所有用户的锁定状态与失败计数清零：
> ```bash
> sudo ./deploy.sh unlock
> # 或
> sudo systemctl restart wallfacer
> ```

---

## 七、Vue 3 前端开发与生产打包

进入 `frontend` 目录：

```bash
cd frontend
npm install
```

1. **本地开发调试模式**：
   ```bash
   npm run dev
   ```
   默认监听 `http://localhost:5173`，所有 `/api/*` 请求会自动代理至 `http://127.0.0.1:8080`。

2. **生产环境打包编译**：
   ```bash
   npm run build
   ```
   编译完成后会在 `frontend/dist/` 目录下生成生产静态资源（`index.html` 与 `assets/`）。

---

## 八、Nginx 生产环境配置指南

在生产环境中，推荐使用 **Nginx** 托管 Vue 3 编译生成的静态目录（`frontend/dist` 或 `/opt/wallfacer/frontend/dist`），并将 `/api/` 接口请求反向代理至 Go 后端（`127.0.0.1:8080`）。

将打包好的 `frontend/dist` 上传至服务器（例如 `/opt/wallfacer/frontend/dist`），然后在 `/etc/nginx/conf.d/wallfacer.conf` 中添加如下配置：

### 1. 标准 HTTP 配置模板

```nginx
server {
    listen 80;
    server_name forwarder.example.com; # 替换为你的域名或服务器 IP

    # 前端 Vue 3 静态资源目录（指向 npm run build 生成的 dist 目录）
    root /opt/wallfacer/frontend/dist;
    index index.html;

    # 开启 Gzip 压缩加速前端静态资源加载
    gzip on;
    gzip_min_length 1k;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/javascript application/json application/javascript application/x-javascript application/xml;

    # 安全响应头加固
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # 1. 反向代理后端 API 接口到 Go 服务
    location /api/ {
        proxy_pass http://127.0.0.1:8080/api/;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 10s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;
    }

    # 2. 前端静态资源缓存策略（Vite 带 hash 的静态文件可长期缓存）
    location /assets/ {
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }

    # 3. Vue 3 单页应用路由兜底
    location / {
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }
}
```

### 2. HTTPS (SSL/TLS) 生产加固配置模板（推荐）

```nginx
server {
    listen 80;
    server_name forwarder.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name forwarder.example.com;

    # SSL 证书配置
    ssl_certificate     /etc/nginx/ssl/forwarder.example.com.pem;
    ssl_certificate_key /etc/nginx/ssl/forwarder.example.com.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    root /opt/wallfacer/frontend/dist;
    index index.html;

    # 反向代理 Go 后端 API
    location /api/ {
        proxy_pass http://127.0.0.1:8080/api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # 静态资源缓存
    location /assets/ {
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }

    # Vue 3 前端入口
    location / {
        try_files $uri $uri/ /index.html;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
    }
}
```

配置完成后检测并重载 Nginx：

```bash
sudo nginx -t && sudo systemctl reload nginx
```
