// secure-code-ui/src/widgets/AuthLayout.tsx
//
// Centered auth container used by the login / forgot-password /
// reset-password routes. Port of the antd Layout/Flex version onto a
// single flex container that inherits SCCAP tokens.

import React from "react";

interface AuthLayoutProps {
  children: React.ReactNode;
}

const AuthLayout: React.FC<AuthLayoutProps> = ({ children }) => (
  <div
    style={{
      minHeight: "100vh",
      background: "var(--bg)",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: 20,
    }}
  >
    <div style={{ width: "100%", maxWidth: 420 }}>{children}</div>
  </div>
);

export default AuthLayout;
