import React from "react";
import { Layout, Flex } from "antd";

const { Content } = Layout;

interface AuthLayoutProps {
  children: React.ReactNode;
}

const AuthLayout: React.FC<AuthLayoutProps> = ({ children }) => {
  return (
    <Layout
      style={{
        minHeight: "100vh",
        backgroundColor: "#f0f2f5" /* Example background */,
      }}
    >
      <Content>
        <Flex
          align="center"
          justify="center"
          style={{ minHeight: "100vh", padding: "20px" }}
        >
          <div style={{ minWidth: "300px", maxWidth: "400px", width: "100%" }}>
            {children}
          </div>
        </Flex>
      </Content>
    </Layout>
  );
};

export default AuthLayout;
