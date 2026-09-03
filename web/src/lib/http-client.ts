import { getToken, notifyUnauthorized } from "./auth";

const BASE_URL = "/api";
export async function request<T>(
  url: string,
  options?: RequestInit,
): Promise<T> {
  const headers = new Headers(options?.headers);
  if (options?.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  // 附加鉴权 Token（若已登录）
  const token = getToken();
  if (token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const response = await fetch(`${BASE_URL}${url}`, {
    ...options,
    headers,
  });
  if (!response.ok) {
    // 鉴权失效：清空凭证并通知全局跳转登录页
    if (response.status === 401) {
      notifyUnauthorized();
      throw new Error("未认证，请重新登录");
    }
    const error = await response.text();
    console.error(`API Error ${response.status}: ${error}`);
    throw new Error(
      `API Error ${response.status}: ${error || response.statusText}`,
    );
  }
  const text = await response.text();
  if (!text) return undefined as T;
  try {
    return JSON.parse(text) as T;
  } catch {
    console.error(`API JSON parse error for ${url}:`, text);
    throw new Error(`Invalid JSON response from ${url}`);
  }
}
