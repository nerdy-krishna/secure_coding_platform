// secure-code-ui/src/pages/admin/SMTPSettingsTab.tsx
import React, { useEffect, useState } from 'react';
import { Form, Input, InputNumber, Button, Switch, Typography, message, Card, Spin } from 'antd';
import { SaveOutlined } from '@ant-design/icons';
import apiClient from '../../shared/api/apiClient';

const { Title, Paragraph } = Typography;

const SMTP_CONFIG_KEY = 'system.smtp';

const SMTPSettingsTab: React.FC = () => {
    const [form] = Form.useForm();
    const [loading, setLoading] = useState<boolean>(true);
    const [saving, setSaving] = useState<boolean>(false);

    useEffect(() => {
        const fetchSmtpConfig = async () => {
            try {
                const response = await apiClient.get('/admin/system-config/');
                const configs = response.data;
                const smtpConfig = configs.find((c: any) => c.key === SMTP_CONFIG_KEY);

                if (smtpConfig && smtpConfig.value) {
                    form.setFieldsValue(smtpConfig.value);
                } else {
                    // Set sensible defaults if none exists
                    form.setFieldsValue({
                        host: '',
                        port: 587,
                        user: '',
                        password: '',
                        from: '',
                        tls: true,
                        ssl: false
                    });
                }
            } catch (error) {
                console.error("Failed to fetch SMTP config:", error);
                message.error("Could not load current SMTP settings.");
            } finally {
                setLoading(false);
            }
        };

        fetchSmtpConfig();
    }, [form]);

    const onFinish = async (values: any) => {
        setSaving(true);
        // We structure the payload to match what SystemConfigTab expects
        const payload = {
            key: SMTP_CONFIG_KEY,
            value: values,
            description: "Dedicated SMTP Configuration",
            is_secret: true, // Mark as secret to hide password in raw logs if possible
            encrypted: false
        };

        try {
            await apiClient.put(`/admin/system-config/${SMTP_CONFIG_KEY}`, payload);
            message.success("SMTP Configuration saved successfully!");
        } catch (error) {
            console.error("Failed to save SMTP config:", error);
            message.error("Failed to save SMTP preferences.");
        } finally {
            setSaving(false);
        }
    };

    if (loading) {
        return <Spin tip="Loading SMTP Settings..." style = {{ display: 'block', margin: '40px auto' }
    } />;
}

return (
    <Card>
    <Title level= { 4} > SMTP Email Configuration </Title>
        <Paragraph>
                Configure the outgoing mail server details required to send password reset and user invitation emails.
            </Paragraph>

    < Form
form = { form }
layout = "vertical"
onFinish = { onFinish }
style = {{ maxWidth: '600px', marginTop: '24px' }}
            >
    <Form.Item
                    name="host"
label = "SMTP Host (Server)"
rules = { [{ required: true, message: 'Please enter the SMTP host address' }]}
    >
    <Input placeholder="e.g. smtp.sendgrid.net" />
        </Form.Item>

        < Form.Item
name = "port"
label = "SMTP Port"
rules = { [{ required: true, message: 'Please enter the SMTP port' }]}
    >
    <InputNumber style={ { width: '100%' } } placeholder = "e.g. 587 or 465" />
        </Form.Item>

        < Form.Item
name = "user"
label = "SMTP Username"
rules = { [{ required: true, message: 'Please enter the SMTP username' }]}
    >
    <Input placeholder="e.g. apikey or user@domain.com" />
        </Form.Item>

        < Form.Item
name = "password"
label = "SMTP Password"
rules = { [{ required: true, message: 'Please enter the SMTP password' }]}
    >
    <Input.Password placeholder="Enter password / API key" />
        </Form.Item>

        < Form.Item
name = "from"
label = "Sender Address ('From')"
rules = {
    [
    { required: true, message: 'Please enter the sender email address' },
    { type: 'email', message: 'Please enter a valid email address' }
    ]}
    >
    <Input placeholder="e.g. noreply@domain.com" />
        </Form.Item>

        < div style = {{ display: 'flex', gap: '32px' }}>
            <Form.Item
                        name="tls"
label = "Use TLS (STARTTLS)"
valuePropName = "checked"
    >
    <Switch />
    </Form.Item>

    < Form.Item
name = "ssl"
label = "Use SSL"
valuePropName = "checked"
    >
    <Switch />
    </Form.Item>
    </div>

    < Form.Item style = {{ marginTop: '16px' }}>
        <Button type="primary" htmlType = "submit" icon = {< SaveOutlined />} loading = { saving } >
            Save SMTP Settings
                </Button>
                </Form.Item>
                </Form>
                </Card>
    );
};

export default SMTPSettingsTab;
