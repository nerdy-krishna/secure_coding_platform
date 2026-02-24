import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Layout, Tabs, Typography, theme } from 'antd';
import { SettingOutlined, RobotOutlined } from '@ant-design/icons';
import SystemConfigTab from './SystemConfigTab';
import LLMConfigTab from './LLMConfigTab';
import UserManagementTab from './UserManagement';
import SMTPSettingsTab from './SMTPSettingsTab';
import { UserOutlined, MailOutlined } from '@ant-design/icons';

const { Content } = Layout;
const { Title } = Typography;

const AdminDashboard: React.FC = () => {
    const {
        token: { colorBgContainer, borderRadiusLG },
    } = theme.useToken();
    const [searchParams, setSearchParams] = useSearchParams();
    const [activeTab, setActiveTab] = useState<string>(searchParams.get('tab') || 'system');

    useEffect(() => {
        const tab = searchParams.get('tab');
        if (tab && ['system', 'llm', 'users', 'smtp'].includes(tab)) {
            setActiveTab(tab);
        }
    }, [searchParams]);

    const handleTabChange = (key: string) => {
        setActiveTab(key);
        setSearchParams({ tab: key });
    };

    const items = [
        {
            key: 'system',
            label: (
                <span>
                <SettingOutlined />
                    System Settings
                </ span >
            ),
children: <SystemConfigTab />,
        },
{
    key: 'llm',
        label: (
            <span>
            <RobotOutlined />
                    LLM Configurations
        </span>
            ),
    children: <LLMConfigTab />,
},
{
    key: 'users',
        label: (
            <span>
            <UserOutlined />
                    User Management
        </span>
            ),
    children: <UserManagementTab />,
},
{
    key: 'smtp',
        label: (
            <span>
            <MailOutlined />
            SMTP Settings
        </span>
    ),
    children: <SMTPSettingsTab />,
},
    ];

return (
    <Content style= {{ padding: '0 48px', marginTop: 24 }}>
        <div style={ { marginBottom: 24 } }>
            <Title level={ 2 }> Admin Dashboard </Title>
                </div>
                < div
style = {{
    padding: 24,
        minHeight: 380,
            background: colorBgContainer,
                borderRadius: borderRadiusLG,
                }}
            >
    <Tabs
                    defaultActiveKey="system"
activeKey = { activeTab }
onChange = { handleTabChange }
items = { items }
    />
    </div>
    </Content>
    );
};

export default AdminDashboard;
