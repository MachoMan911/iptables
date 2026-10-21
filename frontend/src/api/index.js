const API_BASE =
  (typeof import.meta !== "undefined" && import.meta.env && import.meta.env.VITE_API_BASE_URL) ||
  window.WALLFACER_API_BASE ||
  "";

export const TOKEN_KEY = "ipt_fwd_jwt_token";
export const USER_KEY = "ipt_fwd_username";

export function getToken() {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function clearAuthStorage() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(USER_KEY);
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

export async function apiRequest(path, options = {}, onUnauthorized = null) {
  const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
  const token = getToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  const resp = await fetch(`${API_BASE}${path}`, Object.assign({}, options, { headers }));
  const data = await resp.json().catch(() => ({}));
  if (resp.status === 401) {
    if (path !== "/api/auth/login") {
      clearAuthStorage();
      if (onUnauthorized) onUnauthorized();
      throw new Error(data.detail || "未登录或会话已过期，请重新登录");
    }
    throw new Error(data.detail || "用户名或密码错误");
  }
  if (!resp.ok) {
    throw new Error(data.detail || "请求失败");
  }
  return data;
}

