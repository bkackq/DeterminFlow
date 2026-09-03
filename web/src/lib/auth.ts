/**
 * 前端鉴权工具：Token 存储、登录/登出/状态查询。
 *
 * Token 保存在 localStorage，所有 API 请求与 WebSocket 连接都会携带。
 * 任何请求返回 401 时通过 window 事件广播，由 App 统一跳转到登录页。
 */
export const AUTH_TOKEN_KEY = "determinflow.auth.token";
export const AUTH_USER_KEY = "determinflow.auth.user";

export const AUTH_UNAUTHORIZED_EVENT = "determinflow:auth-unauthorized";

export function getToken(): string | null {
  try {
    return window.localStorage.getItem(AUTH_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function getUsername(): string | null {
  try {
    return window.localStorage.getItem(AUTH_USER_KEY);
  } catch {
    return null;
  }
}

export function setAuth(token: string, username: string): void {
  try {
    window.localStorage.setItem(AUTH_TOKEN_KEY, token);
    window.localStorage.setItem(AUTH_USER_KEY, username);
  } catch {
    // localStorage 不可用时静默失败（隐私模式等），后续请求会触发 401 重定向
  }
}

export function clearAuth(): void {
  try {
    window.localStorage.removeItem(AUTH_TOKEN_KEY);
    window.localStorage.removeItem(AUTH_USER_KEY);
  } catch {
    // ignore
  }
}

/** 通知全局：鉴权已失效，需要重新登录 */
export function notifyUnauthorized(): void {
  clearAuth();
  window.dispatchEvent(new CustomEvent(AUTH_UNAUTHORIZED_EVENT));
}

export interface LoginResult {
  token: string;
  username: string;
  expires_in: number;
}

/** 登录：成功写入 Token 并返回结果；失败抛出带消息的 Error */
export async function login(
  username: string,
  password: string,
): Promise<LoginResult> {
  const response = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  let data: unknown = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  if (!response.ok) {
    const detail =
      data && typeof data === "object" && "detail" in data
        ? String((data as { detail: unknown }).detail)
        : `登录失败（HTTP ${response.status}）`;
    throw new Error(detail);
  }
  const result = data as LoginResult;
  setAuth(result.token, result.username);
  return result;
}

/** 登出：清空本地凭证（Token 为无状态签名，服务端无需注销） */
export async function logout(): Promise<void> {
  try {
    await fetch("/api/auth/logout", {
      method: "POST",
      headers: { Authorization: `Bearer ${getToken() ?? ""}` },
    });
  } catch {
    // 忽略网络错误，本地清空即可
  }
  clearAuth();
}

export interface MeResult {
  authenticated: boolean;
  username?: string;
}

export interface AuthStatus {
  enabled: boolean;
  authenticated: boolean;
  username?: string | null;
}

/**
 * 查询鉴权状态（开放接口）：
 * - enabled=false：后端已关闭鉴权，直接进入主界面
 * - enabled=true && authenticated：当前 Token 有效，直接进入主界面
 * - enabled=true && !authenticated：需要登录
 */
export async function fetchAuthStatus(): Promise<AuthStatus> {
  const response = await fetch("/api/auth/status", {
    headers: getToken()
      ? { Authorization: `Bearer ${getToken()}` }
      : undefined,
  });
  try {
    const data = (await response.json()) as AuthStatus;
    return data;
  } catch {
    return { enabled: false, authenticated: false, username: null };
  }
}

/** 校验当前 Token 是否有效，返回当前用户信息 */
export async function fetchMe(): Promise<MeResult | null> {
  const token = getToken();
  if (!token) return null;
  const response = await fetch("/api/auth/me", {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) return null;
  try {
    return (await response.json()) as MeResult;
  } catch {
    return null;
  }
}

/** 同步判断是否存在本地 Token（用于启动时决定先渲染登录页还是校验） */
export function hasLocalToken(): boolean {
  return getToken() !== null;
}
