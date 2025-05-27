// secure-code-ui/src/pages/auth/RegisterPage.tsx
import React, { useState } from 'react';
import { Form, Input, Button, Typography, Alert, Card } from 'antd';
import { MailOutlined, LockOutlined } from '@ant-design/icons';
import { Link, useNavigate } from 'react-router-dom';
import { registerUser } from '../../services/authService';
import type { UserRegisterData } from '../../types/api';
import AuthLayout from '../../layouts/AuthLayout';

const { Title } = Typography;

const RegisterPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const navigate = useNavigate();
  const [form] = Form.useForm();

  const onFinish = async (values: UserRegisterData) => {
    setLoading(true);
    setError(null);
    setSuccess(null);

    const payload: UserRegisterData = {
      email: values.email,
      password: values.password,
      // is_active, is_superuser, is_verified will default on the backend
    };

    try {
      await registerUser(payload);
      setSuccess('Registration successful! You can now log in.');
      form.resetFields(); // Reset form fields on success
      // Optionally, redirect after a short delay or let user click login
      setTimeout(() => {
        navigate('/login');
      }, 3000); // Redirect after 3 seconds
    } catch (err: any) {
      if (err.response && err.response.data && err.response.data.detail) {
        if (typeof err.response.data.detail === 'string') {
            setError(err.response.data.detail);
        } else if (Array.isArray(err.response.data.detail) && err.response.data.detail.length > 0) {
            // Handle FastAPI validation errors (e.g., from Pydantic models)
             const errorMessages = err.response.data.detail.map((e: any) => {
                if (e.loc && e.msg) {
                    return `${e.loc.join('.')} - ${e.msg}`;
                }
                return 'An unknown validation error occurred.';
            }).join('; ');
            setError(errorMessages);
        } else {
            setError('Registration failed. An unexpected error occurred.');
        }
      } else {
        setError('Registration failed. An unexpected error occurred.');
      }
      console.error('Registration error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout>
      <Card title={<Title level={3} style={{ textAlign: 'center', marginBottom: 0 }}>Create Account</Title>} style={{ boxShadow: '0 4px 8px rgba(0,0,0,0.1)' }}>
        {error && <Alert message={error} type="error" showIcon closable style={{ marginBottom: 20 }} onClose={() => setError(null)} />}
        {success && <Alert message={success} type="success" showIcon style={{ marginBottom: 20 }} />}
        <Form
          form={form}
          name="register"
          onFinish={onFinish}
          scrollToFirstError
          size="large"
        >
          <Form.Item
            name="email"
            rules={[
              { required: true, message: 'Please input your Email!' },
              { type: 'email', message: 'The input is not a valid Email!' },
            ]}
          >
            <Input prefix={<MailOutlined />} placeholder="Email" />
          </Form.Item>

          <Form.Item
            name="password"
            rules={[
              { required: true, message: 'Please input your Password!' },
              { min: 8, message: 'Password must be at least 8 characters!' },
              // You can add more complex regex validation for passwords here if needed
            ]}
            hasFeedback
          >
            <Input.Password prefix={<LockOutlined />} placeholder="Password" />
          </Form.Item>

          <Form.Item
            name="confirm"
            dependencies={['password']}
            hasFeedback
            rules={[
              { required: true, message: 'Please confirm your Password!' },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('password') === value) {
                    return Promise.resolve();
                  }
                  return Promise.reject(new Error('The two passwords that you entered do not match!'));
                },
              }),
            ]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="Confirm Password" />
          </Form.Item>

          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} block>
              Register
            </Button>
          </Form.Item>
          Already have an account? <Link to="/login">Log in here!</Link>
        </Form>
      </Card>
    </AuthLayout>
  );
};

export default RegisterPage;