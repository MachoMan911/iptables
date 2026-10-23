<template>
  <!-- ==================== 登录视图 ==================== -->
  <div v-if="!isLoggedIn" class="login-wrapper">
    <div class="login-card">
      <div class="login-title">
        <span class="brand-dot"></span>
        <span>面壁者转发</span>
      </div>
      <div class="login-subtitle">
        等保三级安全认证 (RSA-2048 加密传输 · 防重放 · 防爆破锁定)
      </div>
      <form autocomplete="off" @submit.prevent="handleLogin">
        <div class="form-group">
          <label class="form-label">管理员账号</label>
          <input
            v-model="loginForm.username"
            type="text"
            class="form-control"
            placeholder="请输入管理员账号"
            autocomplete="off"
            autocapitalize="off"
            spellcheck="false"
            @copy.prevent
            @cut.prevent
            required
          />
        </div>
        <div class="form-group">
          <label class="form-label">登录密码</label>
          <input
            v-model="loginForm.password"
            type="password"
            class="form-control"
            placeholder="请输入登录密码"
            autocomplete="new-password"
            @copy.prevent
            @cut.prevent
            @contextmenu.prevent
            required
          />
          <div class="form-hint">账号与密码均经 RSA-2048 + 一次性挑战码整体加密传输，全程零明文暴露</div>
        </div>
        <div v-if="loginError" style="color: #f87171; font-size: 13px; margin-bottom: 12px;">
          {{ loginError }}
        </div>
        <button type="submit" class="btn btn-block" :disabled="loggingIn">
          {{ loggingIn ? "安全验证中..." : "安全登录" }}
        </button>
      </form>
    </div>
  </div>

  <!-- ==================== 管理后台主视图 (Vue 3) ==================== -->
  <div v-else>
    <nav class="navbar">
      <div class="nav-brand">
        <span class="brand-dot"></span>
        <span>面壁者转发</span>
        <span class="badge badge-green">等保三级加固</span>
        <span class="badge badge-blue">Go + Vue 3</span>
      </div>
      <div class="nav-actions">
        <span class="user-pill">管理员: <strong>{{ currentUser }}</strong></span>
        <button class="btn btn-outline btn-sm" :disabled="testingDb" @click="testDbConnection">
          {{ testingDb ? "检测中..." : "测试数据库连接" }}
        </button>
        <button class="btn btn-outline btn-sm" @click="showPasswordModal = true">修改密码</button>
        <button class="btn btn-danger btn-sm" @click="handleLogout(true)">退出登录</button>
      </div>
    </nav>

    <div class="container">
      <!-- 顶部 4 张等高对齐状态卡片 -->
      <div class="stats-grid">
        <!-- 卡片 1：转发规则统计 -->
        <div class="stat-card">
          <div>
            <div class="stat-header">
              <span class="stat-title">转发规则统计</span>
              <span class="badge badge-blue">实时生效</span>
            </div>
            <div class="stat-main">
              <span class="stat-number">{{ status.enabled_rules }} / {{ status.total_rules }}</span>
              <span class="stat-unit">已启用 / 总规则</span>
            </div>
          </div>
          <div class="stat-footer">
            <span class="stat-footer-text">
              转发规则配置与持久化管理
            </span>
            <button class="btn btn-outline btn-sm" style="padding: 3px 9px;" :disabled="testingDb" @click="testDbConnection">
              {{ testingDb ? "检测中..." : "测试数据库连接" }}
            </button>
          </div>
        </div>

        <!-- 卡片 2：动态域名监控 -->
        <div class="stat-card">
          <div>
            <div class="stat-header">
              <span class="stat-title">动态域名监控 (DDNS)</span>
              <span class="badge badge-green">运行中</span>
            </div>
            <div class="stat-main">
              <span class="stat-number">{{ status.domain_rules }}</span>
              <span class="stat-unit">条动态域名规则</span>
            </div>
          </div>
          <div class="stat-footer">
            <span class="stat-footer-text">
              检测周期: <strong style="color:var(--text);">{{ status.dns_watcher.interval_seconds }}</strong> 秒
            </span>
            <div style="display:flex; align-items:center; gap:6px;">
              <button class="btn btn-outline btn-sm" style="padding: 3px 9px;" @click="triggerDnsCheckNow">刷新解析</button>
              <button class="btn btn-outline btn-sm" style="padding: 3px 9px;" @click="openIntervalModal">调整周期</button>
            </div>
          </div>
        </div>

        <!-- 卡片 3：跨平台转发引擎状态 -->
        <div class="stat-card">
          <div>
            <div class="stat-header">
              <span class="stat-title">跨平台转发引擎</span>
              <span class="badge" :class="status.iptables.ip_forward_enabled ? 'badge-green' : 'badge-red'">
                {{ status.iptables.ip_forward_enabled ? "已开启" : "未开启" }}
              </span>
            </div>
            <div class="stat-main">
              <span
                class="stat-number"
                style="font-size: 22px;"
                :style="{ color: status.iptables.ip_forward_enabled ? '#34d399' : '#f87171' }"
              >
                {{ status.iptables.ip_forward_enabled ? "内核转发已开启" : "内核转发未开启" }}
              </span>
            </div>
          </div>
          <div class="stat-footer">
            <span class="stat-footer-text">
              最近检测: {{ formatTime(status.dns_watcher.last_run_at) }}
            </span>
          </div>
        </div>

        <!-- 卡片 4：实时速率与总流量 -->
        <div class="stat-card">
          <div>
            <div class="stat-header">
              <span class="stat-title">实时速率 &amp; 累计流量</span>
              <span class="badge badge-purple">实时采样</span>
            </div>
            <div class="stat-main mono" style="font-size: 17px; font-weight: 700; gap: 10px;">
              <span style="color:#34d399;">↑ {{ formatSpeed(status.traffic.total_up_speed) }}</span>
              <span style="color:#334155;">|</span>
              <span style="color:#60a5fa;">↓ {{ formatSpeed(status.traffic.total_down_speed) }}</span>
            </div>
          </div>
          <div class="stat-footer">
            <span class="stat-footer-text mono">
              总计: {{ formatBytes(status.traffic.total_bytes) }} (↑ {{ formatBytes(status.traffic.total_up_bytes) }} / ↓ {{ formatBytes(status.traffic.total_down_bytes) }})
            </span>
          </div>
        </div>
      </div>

      <!-- 工具栏 -->
      <div class="toolbar">
        <div class="tabs">
          <button class="tab-btn" :class="{ active: activeTab === 'rules' }" @click="activeTab = 'rules'">转发规则管理</button>
          <button class="tab-btn" :class="{ active: activeTab === 'logs' }" @click="activeTab = 'logs'">域名 IP 变更日志</button>
          <button class="tab-btn" :class="{ active: activeTab === 'preview' }" @click="activeTab = 'preview'">底层 iptables 规则预览</button>
        </div>

        <div class="action-group">
          <button class="btn btn-outline" @click="triggerDnsCheckNow">立即检测域名 IP</button>
          <button class="btn btn-outline" @click="forceSyncIptables">强制重写 iptables</button>
          <button class="btn" @click="openRuleModal()">+ 新增转发规则</button>
        </div>
      </div>

      <!-- Tab 1: 转发规则列表 -->
      <div v-show="activeTab === 'rules'" class="card">
        <div class="table-responsive">
          <table class="responsive-table">
            <thead>
              <tr>
                <th>规则名称 / 协议</th>
                <th>本机监听 &rarr; 目标地址</th>
                <th>当前生效 IP &amp; 本机 SNAT</th>
                <th>实时上下行速度</th>
                <th>累计流量使用情况</th>
                <th>域名监控状态</th>
                <th style="text-align: right;">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="rules.length === 0" class="empty-row">
                <td colspan="7" class="empty-state">暂无转发规则，点击右上角「+ 新增转发规则」开始配置</td>
              </tr>
              <tr v-for="r in rules" :key="r.id">
                <td data-label="规则名称 / 协议">
                  <div class="cell-content">
                    <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;flex-wrap:wrap;">
                      <span class="mono" style="color:var(--text-muted);font-size:12px;">#{{ r.id }}</span>
                      <strong style="font-size:13.5px;word-break:break-word;">{{ r.name }}</strong>
                    </div>
                    <span class="badge badge-blue mono">{{ r.protocol.toUpperCase() }}</span>
                  </div>
                </td>
                <td data-label="本机监听 → 目标">
                  <div class="cell-content">
                    <div class="mono" style="font-size:13px;font-weight:600;word-break:break-all;">
                      <span style="color:#60a5fa;">0.0.0.0:{{ r.listen_port }}</span>
                      <span style="color:var(--text-muted);margin:0 4px;">&rarr;</span>
                      <span>{{ r.target_host }}:{{ r.target_port }}</span>
                    </div>
                    <div style="margin-top:4px;">
                      <span v-if="r.is_domain" class="badge badge-purple">域名动态解析</span>
                      <span v-else class="badge badge-green">静态 IP</span>
                    </div>
                  </div>
                </td>
                <td data-label="生效 IP & SNAT">
                  <div class="cell-content">
                    <div>
                      目标:
                      <span v-if="r.resolved_ip" class="mono" style="color:#34d399;font-weight:600;">
                        {{ r.resolved_ip }}:{{ r.target_port }}
                      </span>
                      <span v-else class="badge badge-red">解析失败</span>
                    </div>
                    <div class="mono" style="font-size:11.5px;color:var(--text-muted);margin-top:4px;">
                      本机 SNAT: <span style="color:#cbd5e1;">{{ r.snat_ip || status.iptables.default_snat_ip || "-" }}</span>
                    </div>
                  </div>
                </td>
                <td data-label="实时上下行速度">
                  <div class="cell-content">
                    <template v-if="r.enabled">
                      <div class="mono" style="font-size:12.5px;color:#34d399;font-weight:600;white-space:nowrap;">↑ {{ formatSpeed(r.up_speed) }}</div>
                      <div class="mono" style="font-size:12.5px;color:#60a5fa;font-weight:600;white-space:nowrap;">↓ {{ formatSpeed(r.down_speed) }}</div>
                    </template>
                    <span v-else class="mono" style="color:var(--text-muted);font-size:12px;">已停用 (0 B/s)</span>
                  </div>
                </td>
                <td data-label="累计流量统计">
                  <div class="cell-content">
                    <div class="mono" style="font-size:12.5px;font-weight:600;color:var(--text);white-space:nowrap;">
                      总计: {{ formatBytes(r.total_bytes) }}
                    </div>
                    <div class="mono" style="font-size:11.5px;color:var(--text-muted);margin-top:2px;white-space:nowrap;">
                      ↑ {{ formatBytes(r.up_bytes) }} | ↓ {{ formatBytes(r.down_bytes) }}
                    </div>
                  </div>
                </td>
                <td data-label="域名监控状态">
                  <div class="cell-content">
                    <span v-if="r.enabled" class="badge badge-green">已启用</span>
                    <span v-else class="badge badge-yellow">已停用</span>
                    <div v-if="r.last_error" style="color:#f87171;font-size:11.5px;margin-top:4px;" :title="r.last_error">
                      异常: {{ r.last_error.slice(0, 22) }}
                    </div>
                    <div v-else-if="r.is_domain" style="font-size:11.5px;color:var(--text-muted);margin-top:4px;white-space:nowrap;">
                      检测: {{ formatTime(r.last_checked_at) }}
                    </div>
                    <div v-else style="font-size:11.5px;color:var(--text-muted);margin-top:4px;">
                      直连静态 IPv4
                    </div>
                  </div>
                </td>
                <td data-label="操作" class="td-actions">
                  <div class="rule-actions">
                    <button v-if="r.is_domain" class="btn btn-outline btn-sm" @click="refreshRuleDns(r)">刷新解析</button>
                    <button class="btn btn-outline btn-sm" @click="toggleRule(r.id)">{{ r.enabled ? "停用" : "启用" }}</button>
                    <button class="btn btn-outline btn-sm" @click="openRuleModal(r)">编辑</button>
                    <button class="btn btn-outline btn-sm" @click="resetRuleTraffic(r)">清零</button>
                    <button class="btn btn-danger btn-sm" @click="deleteRule(r)">删除</button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Tab 2: 域名 IP 变更日志 -->
      <div v-show="activeTab === 'logs'" class="card">
        <div class="table-responsive">
          <table class="responsive-table">
            <thead>
              <tr>
                <th>记录 ID</th>
                <th>规则名称</th>
                <th>目标域名</th>
                <th>变更前 IP</th>
                <th>变更后新 IP</th>
                <th>自动更新 iptables 时间</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="dnsLogs.length === 0" class="empty-row">
                <td colspan="6" class="empty-state">暂无域名解析 IP 变更记录</td>
              </tr>
              <tr v-for="l in dnsLogs" :key="l.id">
                <td data-label="记录 ID" class="mono">#{{ l.id }}</td>
                <td data-label="规则名称"><strong>{{ l.rule_name }}</strong> <span style="color:var(--text-muted)">(Rule #{{ l.rule_id }})</span></td>
                <td data-label="目标域名" class="mono">{{ l.domain }}</td>
                <td data-label="变更前 IP" class="mono" style="color:var(--text-muted)">{{ l.old_ip || "首次解析" }}</td>
                <td data-label="变更后新 IP" class="mono" style="color:#34d399;font-weight:700;">{{ l.new_ip }}</td>
                <td data-label="更新时间">{{ formatTime(l.created_at) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Tab 3: iptables 命令预览 -->
      <div v-show="activeTab === 'preview'" class="card">
        <div class="preview-header">
          <div>
            <strong>当前生成的自定义链 iptables 转发指令</strong>
            <div style="font-size:12px; color:var(--text-muted); margin-top:2px;">
              所有规则均隔离在专用链 (IPT_FWD_PREROUTING / IPT_FWD_POSTROUTING / IPT_FWD_FORWARD) 中，不会干扰系统原有规则
            </div>
          </div>
          <button class="btn btn-outline btn-sm" @click="loadSystemStatus">刷新预览</button>
        </div>
        <div class="code-box">{{ status.iptables.commands_preview || "# 暂无启用规则" }}</div>
      </div>
    </div>

    <!-- ==================== 弹窗：新增 / 编辑规则 ==================== -->
    <div v-if="showRuleModal" class="modal-backdrop">
      <div class="modal-content">
        <div class="modal-header">
          <div class="modal-title">{{ ruleForm.id ? `编辑转发规则 #${ruleForm.id}` : "新增 iptables 转发规则" }}</div>
          <button class="close-btn" @click="showRuleModal = false">&times;</button>
        </div>
        <form @submit.prevent="submitRule">
          <div class="form-group">
            <label class="form-label">规则备注名称 *</label>
            <input v-model="ruleForm.name" type="text" class="form-control" placeholder="例如：海外节点中转 / 业务API转发" required />
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">转发协议 *</label>
              <select v-model="ruleForm.protocol" class="form-control">
                <option value="tcp+udp">TCP + UDP (同时转发)</option>
                <option value="tcp">仅 TCP</option>
                <option value="udp">仅 UDP</option>
              </select>
            </div>
            <div class="form-group">
              <label class="form-label">本机监听端口 *</label>
              <input v-model.number="ruleForm.listen_port" type="number" class="form-control" min="1" max="65535" required />
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label class="form-label">目标域名或 IPv4 地址 *</label>
              <input v-model="ruleForm.target_host" type="text" class="form-control" placeholder="例如 ddns.example.com 或 1.2.3.4" required />
              <div class="form-hint">填写域名将自动开启定时 DNS 解析检测与动态更新</div>
            </div>
            <div class="form-group">
              <label class="form-label">目标端口 *</label>
              <input v-model.number="ruleForm.target_port" type="number" class="form-control" min="1" max="65535" required />
            </div>
          </div>
          <div class="form-group">
            <label class="form-label">回程 SNAT 本机网卡 IP</label>
            <select v-model="ruleForm.snat_ip" class="form-control">
              <option :value="status.iptables.default_snat_ip">
                自动匹配本机路由网卡 IP ({{ status.iptables.default_snat_ip || "默认" }})
              </option>
              <option v-for="nic in status.iptables.local_nics" :key="nic.ip" :value="nic.ip">
                本机网卡 {{ nic.interface }}: {{ nic.ip }}
              </option>
            </select>
            <div class="form-hint">自动读取本机网卡配置的 IPv4 地址执行 iptables -j SNAT --to-source</div>
          </div>
          <div class="form-group" style="display:flex; align-items:center; gap:8px; margin-top:8px;">
            <input id="ruleEnabledChk" v-model="ruleForm.enabled" type="checkbox" style="width:16px; height:16px;" />
            <label for="ruleEnabledChk" style="font-size:13.5px; cursor:pointer;">保存后立即启用并写入转发引擎</label>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-outline" @click="showRuleModal = false">取消</button>
            <button type="submit" class="btn">保存并生效</button>
          </div>
        </form>
      </div>
    </div>

    <!-- ==================== 弹窗：修改域名检测周期 ==================== -->
    <div v-if="showIntervalModal" class="modal-backdrop">
      <div class="modal-content" style="max-width: 400px;">
        <div class="modal-header">
          <div class="modal-title">设置域名解析定时检测周期</div>
          <button class="close-btn" @click="showIntervalModal = false">&times;</button>
        </div>
        <form @submit.prevent="submitInterval">
          <div class="form-group">
            <label class="form-label">检测间隔时间（秒）</label>
            <input v-model.number="intervalInput" type="number" class="form-control" min="5" max="86400" required />
            <div class="form-hint">建议设置为 30 ~ 300 秒。当检测到域名解析 IP 改变时，将自动更新转发规则。</div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-outline" @click="showIntervalModal = false">取消</button>
            <button type="submit" class="btn">保存设置</button>
          </div>
        </form>
      </div>
    </div>

    <!-- ==================== 弹窗：修改管理员密码 ==================== -->
    <div v-if="showPasswordModal" class="modal-backdrop">
      <div class="modal-content" style="max-width: 440px;">
        <div class="modal-header">
          <div class="modal-title">修改管理员密码（等保三级标准）</div>
          <button class="close-btn" @click="showPasswordModal = false">&times;</button>
        </div>
        <form @submit.prevent="submitPassword">
          <div class="form-group">
            <label class="form-label">当前原密码</label>
            <input v-model="pwdForm.old_password" type="password" class="form-control" required />
          </div>
          <div class="form-group">
            <label class="form-label">新密码（8~64位，需含大小写字母+数字+特殊字符）</label>
            <input v-model="pwdForm.new_password" type="password" class="form-control" minlength="8" maxlength="64" required />
            <div class="form-hint">
              等保三级口令要求：长度 8~64 位，必须同时包含大写字母、小写字母、数字和特殊符号，不能包含账号名，不能有连续 4 位相同字符。
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-outline" @click="showPasswordModal = false">取消</button>
            <button type="submit" class="btn">加密提交修改</button>
          </div>
        </form>
      </div>
    </div>
  </div>

  <div v-if="toast.visible" class="toast" :style="{ borderColor: toast.isError ? '#ef4444' : '#3b82f6' }">
    {{ toast.message }}
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, onUnmounted } from "vue";
import { apiRequest, getToken, clearAuthStorage, TOKEN_KEY, USER_KEY } from "./api/index.js";
import { encryptLoginCredentials, encryptPasswordPayload } from "./utils/crypto.js";

const isLoggedIn = ref(Boolean(getToken()));
const currentUser = ref(sessionStorage.getItem(USER_KEY) || "admin");
const loggingIn = ref(false);
const loginError = ref("");
const activeTab = ref("rules");

const loginForm = reactive({ username: "", password: "" });
const toast = reactive({ visible: false, message: "", isError: false });

const status = reactive({
  total_rules: 0,
  enabled_rules: 0,
  domain_rules: 0,
  db_connected: false,
  traffic: {
    total_up_bytes: 0,
    total_down_bytes: 0,
    total_bytes: 0,
    total_up_speed: 0,
    total_down_speed: 0,
  },
  dns_watcher: {
    is_running: true,
    interval_seconds: 60,
    last_run_at: null,
  },
  iptables: {
    dry_run: false,
    is_linux: false,
    is_macos: false,
    ip_forward_enabled: true,
    default_snat_ip: "",
    local_nics: [],
    commands_preview: "",
  },
});

const rules = ref([]);
const dnsLogs = ref([]);

const showRuleModal = ref(false);
const showIntervalModal = ref(false);
const showPasswordModal = ref(false);
const testingDb = ref(false);

const ruleForm = reactive({
  id: null,
  name: "",
  protocol: "tcp+udp",
  listen_port: 10080,
  target_host: "",
  target_port: 443,
  snat_ip: "",
  enabled: true,
});

const intervalInput = ref(60);
const pwdForm = reactive({ old_password: "", new_password: "" });

let toastTimer = null;
function showToast(msg, isError = false) {
  toast.message = msg;
  toast.isError = isError;
  toast.visible = true;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.visible = false;
  }, 3200);
}

function formatTime(isoStr) {
  if (!isoStr) return "-";
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return isoStr;
  return d.toLocaleString("zh-CN", { hour12: false });
}

function formatBytes(bytes) {
  const b = Number(bytes || 0);
  if (b < 1024) {
    return (Number.isInteger(b) ? b : b.toFixed(2)) + " B";
  }
  const units = ["KB", "MB", "GB", "TB"];
  let val = b / 1024;
  let idx = 0;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return val.toFixed(2) + " " + units[idx];
}

function formatSpeed(bytesPerSec) {
  const b = Number(bytesPerSec || 0);
  if (b < 1024) {
    return b.toFixed(2) + " B/s";
  }
  return formatBytes(b) + "/s";
}

async function handleLogin() {
  loginError.value = "";
  loggingIn.value = true;
  try {
    const challenge = await apiRequest("/api/auth/challenge");
    const encrypted_credentials = encryptLoginCredentials(
      loginForm.username.trim(),
      loginForm.password,
      challenge
    );
    loginForm.password = "";

    const data = await apiRequest("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        encrypted_credentials,
        nonce: challenge.nonce,
      }),
    });
    sessionStorage.setItem(TOKEN_KEY, data.access_token);
    sessionStorage.setItem(USER_KEY, data.username);
    currentUser.value = data.username;
    loginForm.username = "";
    isLoggedIn.value = true;
    await Promise.all([loadSystemStatus(), loadRules(), loadDnsLogs()]);
  } catch (err) {
    loginError.value = err.message;
  } finally {
    loggingIn.value = false;
  }
}

function handleLogout(notify = true) {
  clearAuthStorage();
  isLoggedIn.value = false;
  if (notify) showToast("已安全退出登录");
}

async function loadSystemStatus() {
  if (!isLoggedIn.value) return;
  try {
    const st = await apiRequest("/api/status", {}, () => handleLogout(false));
    Object.assign(status, st);
  } catch (err) {
    console.error(err);
  }
}

async function loadRules() {
  if (!isLoggedIn.value) return;
  try {
    rules.value = await apiRequest("/api/rules", {}, () => handleLogout(false));
  } catch (err) {
    console.error(err);
  }
}

async function loadDnsLogs() {
  if (!isLoggedIn.value) return;
  try {
    dnsLogs.value = await apiRequest("/api/dns/logs", {}, () => handleLogout(false));
  } catch (err) {
    console.error(err);
  }
}

async function testDbConnection() {
  testingDb.value = true;
  try {
    const res = await apiRequest("/api/db/test", { method: "POST" });
    showToast(res.message, !res.connected);
    await Promise.all([loadSystemStatus(), loadRules(), loadDnsLogs()]);
  } catch (err) {
    showToast(err.message, true);
  } finally {
    testingDb.value = false;
  }
}

function openRuleModal(r = null) {
  if (r) {
    ruleForm.id = r.id;
    ruleForm.name = r.name;
    ruleForm.protocol = r.protocol;
    ruleForm.listen_port = r.listen_port;
    ruleForm.target_host = r.target_host;
    ruleForm.target_port = r.target_port;
    ruleForm.snat_ip = r.snat_ip || status.iptables.default_snat_ip || "";
    ruleForm.enabled = r.enabled;
  } else {
    ruleForm.id = null;
    ruleForm.name = "";
    ruleForm.protocol = "tcp+udp";
    ruleForm.listen_port = "";
    ruleForm.target_host = "";
    ruleForm.target_port = "";
    ruleForm.snat_ip = status.iptables.default_snat_ip || "";
    ruleForm.enabled = true;
  }
  showRuleModal.value = true;
}

async function submitRule() {
  const payload = {
    name: ruleForm.name.trim(),
    protocol: ruleForm.protocol,
    listen_port: Number(ruleForm.listen_port),
    target_host: ruleForm.target_host.trim(),
    target_port: Number(ruleForm.target_port),
    snat_ip: ruleForm.snat_ip || null,
    enabled: ruleForm.enabled,
  };
  try {
    if (ruleForm.id) {
      await apiRequest(`/api/rules/${ruleForm.id}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      showToast("规则更新成功并已同步至转发引擎");
    } else {
      await apiRequest("/api/rules", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      showToast("新转发规则已创建并生效");
    }
    showRuleModal.value = false;
    await Promise.all([loadRules(), loadSystemStatus(), loadDnsLogs()]);
  } catch (err) {
    showToast(err.message, true);
  }
}

async function toggleRule(id) {
  try {
    await apiRequest(`/api/rules/${id}/toggle`, { method: "POST" });
    showToast("规则状态已切换");
    await Promise.all([loadRules(), loadSystemStatus()]);
  } catch (err) {
    showToast(err.message, true);
  }
}

async function resetRuleTraffic(r) {
  if (!confirm(`确定要将规则「${r.name}」的累计上下行流量清零吗？`)) return;
  try {
    await apiRequest(`/api/rules/${r.id}/reset-traffic`, { method: "POST" });
    showToast("该规则累计流量已清零");
    await Promise.all([loadRules(), loadSystemStatus()]);
  } catch (err) {
    showToast(err.message, true);
  }
}

async function deleteRule(r) {
  if (!confirm(`确定要删除转发规则「${r.name}」吗？`)) return;
  try {
    await apiRequest(`/api/rules/${r.id}`, { method: "DELETE" });
    showToast("规则已删除");
    await Promise.all([loadRules(), loadSystemStatus()]);
  } catch (err) {
    showToast(err.message, true);
  }
}

async function triggerDnsCheckNow() {
  try {
    showToast("正在刷新所有域名解析并覆盖生效 IP 配置...");
    const res = await apiRequest("/api/dns/check-now", { method: "POST" });
    showToast(`刷新完成：已解析 ${res.checked_count} 条域名规则并覆盖配置（其中 ${res.changed_count} 条 IP 发生变更）`);
    await Promise.all([loadRules(), loadSystemStatus(), loadDnsLogs()]);
  } catch (err) {
    showToast(err.message, true);
  }
}

async function refreshRuleDns(r) {
  try {
    const res = await apiRequest(`/api/rules/${r.id}/resolve`, { method: "POST" });
    showToast(res.message);
    await Promise.all([loadRules(), loadSystemStatus(), loadDnsLogs()]);
  } catch (err) {
    showToast(err.message, true);
  }
}

async function forceSyncIptables() {
  try {
    const res = await apiRequest("/api/rules/sync", { method: "POST" });
    showToast(res.message);
    await loadSystemStatus();
  } catch (err) {
    showToast(err.message, true);
  }
}

function openIntervalModal() {
  intervalInput.value = status.dns_watcher.interval_seconds || 60;
  showIntervalModal.value = true;
}

async function submitInterval() {
  try {
    const res = await apiRequest("/api/dns/interval", {
      method: "PUT",
      body: JSON.stringify({ interval_seconds: Number(intervalInput.value) }),
    });
    showToast(res.message);
    showIntervalModal.value = false;
    await loadSystemStatus();
  } catch (err) {
    showToast(err.message, true);
  }
}

async function submitPassword() {
  try {
    const challenge = await apiRequest("/api/auth/challenge");
    const encrypted_old_password = encryptPasswordPayload(pwdForm.old_password, challenge);
    const encrypted_new_password = encryptPasswordPayload(pwdForm.new_password, challenge);
    const res = await apiRequest("/api/auth/password", {
      method: "PUT",
      body: JSON.stringify({
        encrypted_old_password,
        encrypted_new_password,
        nonce: challenge.nonce,
      }),
    });
    showToast(res.message);
    pwdForm.old_password = "";
    pwdForm.new_password = "";
    showPasswordModal.value = false;
  } catch (err) {
    showToast(err.message, true);
  }
}

let pollTimer = null;
onMounted(() => {
  if (isLoggedIn.value) {
    Promise.all([loadSystemStatus(), loadRules(), loadDnsLogs()]);
  }
  pollTimer = setInterval(() => {
    if (isLoggedIn.value) {
      loadSystemStatus();
      loadRules();
    }
  }, 1500);
});

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer);
});
</script>

