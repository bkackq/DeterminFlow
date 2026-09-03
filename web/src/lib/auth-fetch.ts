import { getToken } from "./auth";

/**
 * 全局 fetch 鉴权包装。
 *
 * 前端大量模块直接使用原生 fetch 调用 `/api/*` 接口，若逐一改造调用点容易遗漏。
 * 这里在应用启动时包装全局 fetch：
 * - 仅对同源受保护接口（以 /api 或 /ws 开头的相对路径）自动附加 Authorization 头；
 * - 外部绝对 URL 不附加，避免 Token 泄露给第三方服务；
 * - 已在 header 中手动设置过 Authorization 的不重复覆盖。
 */
export function installAuthFetch(): void {
  const originalFetch = window.fetch.bind(window);

  function isProtectedApi(input: RequestInfo | URL): boolean {
    let url: string;
    if (typeof input === "string") {
      url = input;
    } else if (input instanceof URL) {
      url = input.href;
    } else {
      url = input.url;
    }
    // 相对路径且指向受保护前缀
    return (
      (url.startsWith("/api/") || url.startsWith("/api") ||
        url.startsWith("/ws/") || url.startsWith("/ws")) &&
      !/^[a-z][a-z0-9+.-]*:\/\//i.test(url)
    );
  }

  const wrappedFetch: typeof fetch = async (input, init) => {
    if (isProtectedApi(input)) {
      const token = getToken();
      if (token) {
        const headers = new Headers(init?.headers);
        if (!headers.has("Authorization")) {
          headers.set("Authorization", `Bearer ${token}`);
        }
        return originalFetch(input, { ...init, headers });
      }
    }
    return originalFetch(input, init);
  };

  window.fetch = wrappedFetch;
}
