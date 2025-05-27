import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { ConfigProvider } from 'antd';
import 'antd/dist/reset.css'; // Ant Design's global reset style
import './index.css'; // Your project's global styles (if any)

// Optional: Configure a default theme for Ant Design
// You can customize this later in a separate theme file
const antdTheme = {
  token: {
    // Example: Change primary color
    // colorPrimary: '#00b96b',
  },
};

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider theme={antdTheme}>
      <App />
    </ConfigProvider>
  </React.StrictMode>
);