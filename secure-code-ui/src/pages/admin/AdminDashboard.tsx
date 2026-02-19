import React, { useState } from 'react';
import { Layout, Tabs, Typography, theme } from 'antd';
import { SettingOutlined, RobotOutlined } from '@ant-design/icons';
import SystemConfigTab from './SystemConfigTab';
import LLMConfigTab from './LLMConfigTab';

const { Content } = Layout;
const { Title } = Typography;

const AdminDashboard: React.FC = () => {
    const {
        token: { colorBgContainer, borderRadiusLG },
    } = theme.useToken();
    const [activeTab, setActiveTab] = useState<string>('system');

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
onChange = { setActiveTab }
items = { items }
    />
    </div>
    </Content>
    );
};

export default AdminDashboard;
