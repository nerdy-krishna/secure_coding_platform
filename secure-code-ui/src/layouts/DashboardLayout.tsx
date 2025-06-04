// secure-code-ui/src/layouts/DashboardLayout.tsx
import {
  BellOutlined,
  DesktopOutlined,
  FileTextOutlined,
  LogoutOutlined,
  PieChartOutlined,
  SettingOutlined,
  UserOutlined,
} from "@ant-design/icons";
import type { MenuProps } from "antd";
import {
  Avatar,
  Button, // <-- ADDED Button
  Dropdown,
  Layout,
  Menu,
  Space,
  Tooltip, // <-- ADDED Tooltip
  Typography,
  theme as antdTheme,
} from "antd";
import React, { useState } from "react";
import { Link } from "react-router-dom"; // useNavigate removed if not used
import { useAuth } from "../hooks/useAuth"; // <-- CORRECTED PATH

const { Header, Content, Footer, Sider } = Layout;
const { Text } = Typography;

type MenuItem = Required<MenuProps>["items"][number];

function getItem(
  label: React.ReactNode,
  key: React.Key,
  icon?: React.ReactNode,
  children?: MenuItem[],
): MenuItem {
  return { key, icon, children, label } as MenuItem;
}

const siderMenuItems: MenuItem[] = [
  getItem(
    <Link to="/dashboard">Dashboard</Link>,
    "dashboard_overview",
    <PieChartOutlined />,
  ),
  getItem(
    <Link to="/submit">Submit Code</Link>,
    "submit_code",
    <FileTextOutlined />,
  ),
  getItem(
    <Link to="/history">History</Link>,
    "submission_history",
    <DesktopOutlined />,
  ),
  // getItem("Team", "team_sub", <TeamOutlined />, [ // Example a sub-menu
  //   getItem("Team 1", "team_1"),
  //   getItem("Team 2", "team_2"),
  // ]),
  getItem(
    <Link to="/profile">User Profile</Link>,
    "user_profile_nav",
    <UserOutlined />,
  ),
  getItem(
    <Link to="/settings">Settings</Link>,
    "user_settings_nav",
    <SettingOutlined />,
  ),
];

const DashboardLayout: React.FC<{ children?: React.ReactNode }> = ({
  children,
}) => {
  const [collapsed, setCollapsed] = useState(false);
  // const navigate = useNavigate(); // REMOVE if not used
  const { logout, user } = useAuth();
  const {
    token: { colorBgContainer, borderRadiusLG },
  } = antdTheme.useToken();

  const handleLogout = async () => {
    console.log("DashboardLayout: Logout button clicked.");
    try {
      await logout();
      // Navigation to /login should be handled by App.tsx routing logic
      // due to accessToken becoming null in AuthContext
    } catch (error) {
      console.error("DashboardLayout: Error during logout:", error);
    }
  };

  const userAccountMenuItems: MenuProps["items"] = [
    {
      key: "profile",
      label: (
        <Link to="/profile">
          <UserOutlined style={{ marginRight: 8 }} />
          Profile
        </Link>
      ),
    },
    {
      key: "settings",
      label: (
        <Link to="/settings">
          <SettingOutlined style={{ marginRight: 8 }} />
          Settings
        </Link>
      ),
    },
    {
      type: "divider",
    },
    {
      key: "logout",
      icon: <LogoutOutlined style={{ marginRight: 8 }} />,
      label: "Logout",
      onClick: handleLogout, // More idiomatic way to handle menu item click
    },
  ];

  return (
    <Layout style={{ minHeight: "100vh" }}>
      <Sider
        collapsible
        collapsed={collapsed}
        onCollapse={(value) => setCollapsed(value)}
      >
        <div
          style={{
            height: 32,
            margin: 16,
            background: "rgba(255, 255, 255, 0.2)",
            borderRadius: 6,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            overflow: "hidden",
          }}
        >
          <Text
            style={{
              color: "white",
              fontSize: collapsed ? "12px" : "16px",
              fontWeight: "bold",
            }}
          >
            {collapsed ? "S" : "SCP"}
          </Text>
        </div>
        <Menu
          theme="dark"
          defaultSelectedKeys={["dashboard_overview"]}
          mode="inline"
          items={siderMenuItems}
        />
      </Sider>
      <Layout className="site-layout">
        {" "}
        {/* Added className for potential specific styling */}
        <Header
          style={{
            padding: "0 24px",
            background: colorBgContainer,
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
          }}
        >
          <div>{/* Placeholder for breadcrumbs or page title */}</div>
          <Space align="center" size="middle">
            <Tooltip title="Notifications">
              <Button shape="circle" icon={<BellOutlined />} />
            </Tooltip>
            <Dropdown
              menu={{ items: userAccountMenuItems }}
              trigger={["click"]}
            >
              <a
                onClick={(e) => e.preventDefault()}
                style={{
                  display: "flex",
                  alignItems: "center",
                  cursor: "pointer",
                }}
              >
                <Avatar
                  size="small"
                  icon={<UserOutlined />}
                  style={{ marginRight: 8 }}
                />
                <Text>{user ? user.email : "User"}</Text>
              </a>
            </Dropdown>
          </Space>
        </Header>
        <Content style={{ margin: "24px 16px 0", overflow: "initial" }}>
          <div
            style={{
              padding: 24,
              background: colorBgContainer,
              borderRadius: borderRadiusLG,
              minHeight: "calc(100vh - 64px - 48px - 69px)", // Example: 100vh - header - content_margin_top_bottom - footer
              // Adjust these values based on your actual layout heights
            }}
          >
            {children}{" "}
            {/* This renders the <Outlet /> passed from ProtectedRoutesWithLayout */}
          </div>
        </Content>
        <Footer style={{ textAlign: "center" }}>
          Secure Code Platform ©{new Date().getFullYear()}
        </Footer>
      </Layout>
    </Layout>
  );
};

export default DashboardLayout;
