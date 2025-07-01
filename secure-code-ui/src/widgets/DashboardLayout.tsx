// secure-code-ui/src/widgets/DashboardLayout.tsx
import {
  BellOutlined,
  DesktopOutlined,
  DollarOutlined,
  FileTextOutlined,
  LogoutOutlined,
  PieChartOutlined,
  ProfileOutlined,
  SettingOutlined,
  ToolOutlined, // <-- Ensure ToolOutlined is imported for the Admin menu
  UserOutlined,
} from "@ant-design/icons";
import type { MenuProps } from "antd";
import {
  Avatar,
  Button,
  Dropdown,
  Layout,
  Menu,
  Space,
  Tooltip,
  Typography,
  theme as antdTheme,
} from "antd";
import React, { useMemo, useState } from "react"; // <-- useMemo is added
import { Link } from "react-router-dom";
import { useAuth } from "../shared/hooks/useAuth";

const { Header, Content, Footer, Sider } = Layout;

type MenuItem = Required<MenuProps>["items"][number];

// This helper function creates menu items. It can be kept outside the component.
function getItem(
  label: React.ReactNode,
  key: React.Key,
  icon?: React.ReactNode,
  children?: MenuItem[],
): MenuItem {
  return { key, icon, children, label } as MenuItem;
}

const DashboardLayout: React.FC<{ children?: React.ReactNode }> = ({
  children,
}) => {
  const [collapsed, setCollapsed] = useState(false);
  const { logout, user } = useAuth(); // Get the user object from our auth hook
  const {
    token: { colorBgContainer, borderRadiusLG },
  } = antdTheme.useToken();

  // --- DYNAMIC SIDEBAR MENU ---
  // We use useMemo to create the menu items so they only recalculate when the user's status changes.
  const siderMenuItems = useMemo(() => {
    const items: MenuItem[] = [
      getItem(
        <Link to="/account/dashboard">Dashboard</Link>,
        "dashboard_overview",
        <PieChartOutlined />,
      ),
      getItem(
        <Link to="/submission/submit">Submit Code</Link>,
        "submit_code",
        <FileTextOutlined />,
      ),
      getItem(
        <Link to="/analysis/results">Analysis Results</Link>,
        "analysis_results",
        <ProfileOutlined />,
      ),
      getItem(
        <Link to="/account/history">History</Link>,
        "submission_history",
        <DesktopOutlined />,
      ),
      getItem(
        <Link to="/account/usage">Cost & Usage</Link>,
        "cost_usage",
        <DollarOutlined />,
      ),
    ];

    // Conditionally add the Admin menu if the user is a superuser
    if (user?.is_superuser) {
      items.push(
        getItem("Admin", "admin_section", <ToolOutlined />, [
          getItem(
            <Link to="/account/settings/llm">LLM Settings</Link>,
            "llm_settings_nav",
          ),
          // Future admin links can be added here
        ]),
      );
    }

    // Add a divider and user-specific items at the end
    items.push({ type: "divider" });
    items.push(
      getItem(
        <Link to="/account/profile">User Profile</Link>,
        "user_profile_nav",
        <UserOutlined />,
      ),
      getItem(
        <Link to="/account/settings">Settings</Link>,
        "user_settings_nav",
        <SettingOutlined />,
      ),
    );
    return items;
  }, [user?.is_superuser]);

  const handleLogout = async () => {
    await logout();
  };

  const userAccountMenuItems: MenuProps["items"] = [
    {
      key: "profile",
      label: (
        <Link to="/account/profile">
          <UserOutlined style={{ marginRight: 8 }} />
          Profile
        </Link>
      ),
    },
    {
      key: "settings",
      label: (
        <Link to="/account/settings">
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
      onClick: handleLogout,
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
          <Typography.Text
            style={{
              color: "white",
              fontSize: collapsed ? "12px" : "16px",
              fontWeight: "bold",
            }}
          >
            {collapsed ? "SCP" : "Secure Code"}
          </Typography.Text>
        </div>
        <Menu
          theme="dark"
          defaultSelectedKeys={["dashboard_overview"]}
          mode="inline"
          items={siderMenuItems} // Use the dynamic menu items here
        />
      </Sider>
      <Layout>
        <Header
          style={{
            padding: "0 24px",
            background: colorBgContainer,
            display: "flex",
            alignItems: "center",
            justifyContent: "flex-end",
          }}
        >
          <Space align="center" size="middle">
            <Tooltip title="Notifications">
              <Button shape="circle" icon={<BellOutlined />} />
            </Tooltip>
            <Dropdown menu={{ items: userAccountMenuItems }} trigger={["click"]}>
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
                <Typography.Text>
                  {user ? user.email : "User"}
                </Typography.Text>
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
              minHeight: "calc(100vh - 64px - 48px - 69px)",
            }}
          >
            {children}
          </div>
        </Content>
        <Footer style={{ textAlign: "center" }}>
          Secure Coding Platform ©{new Date().getFullYear()}
        </Footer>
      </Layout>
    </Layout>
  );
};

export default DashboardLayout;