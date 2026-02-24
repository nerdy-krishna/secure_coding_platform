import React, { useState, useEffect } from 'react';
import { Table, Button, Modal, Form, Input, Switch, Typography, message, Space } from 'antd';
import { UserAddOutlined, ReloadOutlined } from '@ant-design/icons';
import { authService } from '../../../shared/api/authService';
import type { UserRead } from '../../../shared/types/api';

const { Title, Text } = Typography;

const UserManagementTab: React.FC = () => {
    const [users, setUsers] = useState<UserRead[]>([]);
    const [loading, setLoading] = useState<boolean>(false);
    const [isModalVisible, setIsModalVisible] = useState<boolean>(false);
    const [form] = Form.useForm();
    const [creating, setCreating] = useState<boolean>(false);

    const fetchUsers = async () => {
        setLoading(true);
        try {
            const data = await authService.adminListUsers();
            setUsers(data);
        } catch (error) {
            console.error("Failed to fetch users:", error);
            message.error("Failed to load users.");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchUsers();
    }, []);

    const columns = [
        {
            title: 'Email',
            dataIndex: 'email',
            key: 'email',
        },
        {
            title: 'Active',
            dataIndex: 'is_active',
            key: 'is_active',
            render: (isActive: boolean) => (isActive ? <Text type= "success" > Yes < /Text> : <Text type="danger">No</Text >),
        },
    {
        title: 'Superuser',
        dataIndex: 'is_superuser',
        key: 'is_superuser',
        render: (isSuper: boolean) => (isSuper ? <Text type= "warning" > Yes < /Text> : <Text>No</Text >),
        },
{
    title: 'Verified',
        dataIndex: 'is_verified',
            key: 'is_verified',
                render: (isVer: boolean) => (isVer ? <Text type= "success" > Yes < /Text> : <Text type="secondary">No</Text >),
}
    ];

const showModal = () => {
    form.resetFields();
    setIsModalVisible(true);
};

const handleCancel = () => {
    setIsModalVisible(false);
};

const handleCreateUser = async (values: any) => {
    setCreating(true);
    try {
        await authService.adminCreateUser({
            email: values.email,
            is_active: values.is_active ?? true,
            is_superuser: values.is_superuser ?? false,
            is_verified: values.is_verified ?? false,
        });
        message.success('User created successfully. A setup email has been sent.');
        setIsModalVisible(false);
        fetchUsers();
    } catch (error) {
        console.error("Failed to create user:", error);
        message.error('Failed to create user. Please check the email.');
    } finally {
        setCreating(false);
    }
};

return (
    <div>
    <div style= {{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Title level={ 4 }> Manage Users </Title>
            < Space >
            <Button icon={ <ReloadOutlined /> } onClick = { fetchUsers } loading = { loading } >
                Refresh
                </Button>
                < Button type = "primary" icon = {< UserAddOutlined />} onClick = { showModal } >
                    Create User
                        </Button>
                        </Space>
                        </div>

                        < Table
dataSource = { users }
columns = { columns }
rowKey = "id"
loading = { loading }
pagination = {{ pageSize: 10 }}
            />

    < Modal
title = "Create New User"
open = { isModalVisible }
onCancel = { handleCancel }
footer = { null}
destroyOnClose
    >
    <Form layout="vertical" form = { form } onFinish = { handleCreateUser } initialValues = {{ is_active: true, is_superuser: false, is_verified: false }}>
        <Form.Item name="email" label = "Email Address" rules = { [{ required: true, type: 'email', message: 'Please provide a valid email.' }]} >
            <Input placeholder="user@example.com" />
                </Form.Item>
                < Form.Item name = "is_active" valuePropName = "checked" >
                    <Switch checkedChildren="Active" unCheckedChildren = "Inactive" />
                        </Form.Item>
                        < Form.Item name = "is_superuser" valuePropName = "checked" >
                            <Switch checkedChildren="Superuser" unCheckedChildren = "Regular" />
                                </Form.Item>
                                < Form.Item name = "is_verified" valuePropName = "checked" tooltip = "Check this if the user doesn't need to verify their email." >
                                    <Switch checkedChildren="Verified" unCheckedChildren = "Unverified" />
                                        </Form.Item>
                                        < Form.Item style = {{ textAlign: 'right', marginTop: 24, marginBottom: 0 }}>
                                            <Space>
                                            <Button onClick={ handleCancel }> Cancel </Button>
                                                < Button type = "primary" htmlType = "submit" loading = { creating } >
                                                    Create & Send Email
                                                        </Button>
                                                        </Space>
                                                        </Form.Item>
                                                        </Form>
                                                        </Modal>
                                                        </div>
    );
};

export default UserManagementTab;
