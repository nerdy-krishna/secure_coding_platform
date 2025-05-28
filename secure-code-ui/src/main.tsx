// secure-code-ui/src/main.tsx
import { App as AntdApp, ConfigProvider } from "antd"; // Import Ant Design's App component and alias it
import "antd/dist/reset.css";
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

const antdTheme = {
  token: {
    // You can customize your theme tokens here
    // colorPrimary: '#00b96b',
  },
};

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ConfigProvider theme={antdTheme}>
      <AntdApp>
        <App />
      </AntdApp>
    </ConfigProvider>
  </React.StrictMode>,
);