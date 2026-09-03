import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { ExtensionProvider } from "./extensions/context";
import { initializeTheme } from "./lib/theme";
import { ThemeProvider } from "./theme";
import { installAuthFetch } from "./lib/auth-fetch";
import "./index.css";

initializeTheme();
// 在应用渲染前安装全局 fetch 鉴权包装，确保所有 /api 请求自动携带 Token
installAuthFetch();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
      <ExtensionProvider>
        <App />
      </ExtensionProvider>
    </ThemeProvider>
  </React.StrictMode>
);
