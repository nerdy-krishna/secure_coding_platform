// secure-code-ui/src/main.tsx
import { App as AntdApp, ConfigProvider } from "antd";
import "antd/dist/reset.css";
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./app/App";
import { ThemeProvider } from "./app/providers/ThemeProvider";
import "./app/styles/index.css";
// Phase G.0: SCCAP design tokens + primitives. Tokens are pure CSS
// custom-properties (no rules applied yet); primitives are opt-in
// classes (`.sccap-btn`, `.chip`, etc.) consumed by new Phase-G pages.
// Ant Design pages render unchanged.
import "./app/styles/tokens.css";
import "./app/styles/primitives.css";

const antdTheme = {
  token: {
    // You can customize your theme tokens here
    // colorPrimary: '#00b96b',
  },
};

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
      <ConfigProvider theme={antdTheme}>
        <AntdApp>
          <App />
        </AntdApp>
      </ConfigProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
