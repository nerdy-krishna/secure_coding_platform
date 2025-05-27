import React, { useState } from 'react';
import { Layout, Menu, Avatar, Typography, Dropdown, Space, theme as antdTheme } from 'antd';
import {
  DesktopOutlined,
  FileTextOutlined,
  PieChartOutlined,
  TeamOutlined,
  UserOutlined,
  LogoutOutlined,
  SettingOutlined,
  BellOutlined,
} from '@ant-design/icons';
import type { MenuProps } from 'antd';
import { Link, Outlet, useNavigate } from 'react-router-dom'; // Outlet for nested content

const { Header, Content, Footer, Sider } = Layout;
const { Text } = Typography;

type MenuItem = Required<MenuProps>['items'][number];

function getItem(
  label: React.ReactNode,
  key: React.Key,
  icon?: React.ReactNode,
  children?: MenuItem[],
): MenuItem {
  return {
    key,
    icon,
    children,
    label,
  } as MenuItem;
}

const items: MenuItem[] = [
  getItem(<Link to="/dashboard">Dashboard</Link>, '1', <PieChartOutlined />),
  getItem(<Link to="/dashboard/submit">Submit Code</Link>, '2', <FileTextOutlined />),
  getItem(<Link to="/dashboard/history">History</Link>, '3', <DesktopOutlined />),
  getItem('Team', 'sub1', <TeamOutlined />, [
    getItem('Team 1', '4'),
    getItem('Team 2', '5'),
  ]),
  getItem(<Link to="/dashboard/profile">User Profile</Link>, '6', <UserOutlined />),
  getItem(<Link to="/dashboard/settings">Settings</Link>, '7', <SettingOutlined />),
];

interface DashboardLayoutProps {
  children: React.ReactNode; // For pages that don't use Outlet
}

const DashboardLayout: React.FC<DashboardLayoutProps> = ({ children }) => {
  const [collapsed, setCollapsed] = useState(false);
  const navigate = useNavigate();
  const {
    token: { colorBgContainer, borderRadiusLG },
  } = antdTheme.useToken();

  const handleLogout = () => {
    // Implement your actual logout logic here
    // e.g., clear token from localStorage, call API, redirect
    localStorage.removeItem('authToken'); // Example
    navigate('/login');
  };

  const userMenuItems: MenuProps['items'] = [
    {
      key: 'profile',
      label: (
        <Link to="/dashboard/profile">
          <UserOutlined style={{ marginRight: 8 }} />
          Profile
        </Link>
      ),
    },
    {
      key: 'settings',
      label: (
        <Link to="/dashboard/settings">
          <SettingOutlined style={{ marginRight: 8 }} />
          Settings
        </Link>
      ),
    },
    {
      type: 'divider',
    },
    {
      key: 'logout',
      label: (
        <div onClick={handleLogout}>
          <LogoutOutlined style={{ marginRight: 8 }} />
          Logout
        </div>
      ),
    },
  ];


  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider collapsible collapsed={collapsed} onCollapse={(value) => setCollapsed(value)}>
        <div style={{
          height: 32,
          margin: 16,
          background: 'rgba(255, 255, 255, 0.2)',
          borderRadius: 6,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          overflow: 'hidden'
        }}>
          <Text style={{ color: 'white', display: collapsed ? 'none' : 'block' }}>SCP</Text>
          <Text style={{ color: 'white', display: collapsed ? 'block' : 'none' }}>S</Text>
        </div>
        <Menu theme="dark" defaultSelectedKeys={['1']} mode="inline" items={items} />
      </Sider>
      <Layout>
        <Header style={{ padding: '0 16px', background: colorBgContainer, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>{/* Can add breadcrumbs or page titles here */}</div>
          <Space size="middle">
            <BellOutlined style={{ fontSize: '18px' }} /> {/* Placeholder for notifications */}
            <Dropdown menu={{ items: userMenuItems }} trigger={['click']}>
              <a onClick={(e) => e.preventDefault()} style={{ display: 'flex', alignItems: 'center' }}>
                <Avatar size="small" icon={<UserOutlined />} style={{ marginRight: 8 }} />
                <Text>Username</Text> {/* Replace with actual username */}
              </a>
            </Dropdown>
          </Space>
        </Header>
        <Content style={{ margin: '16px' }}>
          <div
            style={{
              padding: 24,
              minHeight: 360,
              background: colorBgContainer,
              borderRadius: borderRadiusLG,
            }}
          >
            {children} {/* This renders the page component passed by the Route */}
          </div>
        </Content>
        <Footer style={{ textAlign: 'center' }}>
          Secure Code Platform ©{new Date().getFullYear()} Created with Ant Design
        </Footer>
      </Layout>
    </Layout>
  );
};

export default DashboardLayout;