// secure-code-ui/src/pages/auth/LoginPage.tsx
import React, { useState } from 'react';
import { Form, Input, Button, Checkbox, Typography, Alert, Card } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';
import { Link, useNavigate } from 'react-router-dom';
import { loginUser } from '../../services/authService';
import type { UserLoginData } from '../../types/api';
import AuthLayout from '../../layouts/AuthLayout'; // Import the layout

const { Title } = Typography;

const LoginPage: React.FC = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const onFinish = async (values: UserLoginData /* Antd Form values match UserLoginData */) => {
    setLoading(true);
    setError(null);
    try {
      // 'username' in UserLoginData is used for email for FastAPI Users
      const loginPayload: UserLoginData = {
        username: values.username, // This should be the email input
        password: values.password,
        // grant_type: 'password' // FastAPI Users /jwt/login endpoint implies this for form data
      };
      const data = await loginUser(loginPayload);
      localStorage.setItem('authToken', data.access_token); // Store access token
      // The refresh token is handled as an HttpOnly cookie by the backend

      // Optional: Fetch user details after login to confirm or store in context
      // const user = await getCurrentUser();
      // console.log('Logged in user:', user);

      navigate('/dashboard');
    } catch (err: any) {
      if (err.response && err.response.data && err.response.data.detail) {
        if (typeof err.response.data.detail === 'string') {
            setError(err.response.data.detail);
        } else if (Array.isArray(err.response.data.detail) && err.response.data.detail.length > 0) {
            // Handle cases like validation errors from FastAPI Users
            setError(err.response.data.detail.map((e: any) => `${e.loc.join('.')} - ${e.msg}`).join(', '));
        } else {
            setError('Login failed. Please check your credentials.');
        }
      } else {
        setError('Login failed. An unexpected error occurred.');
      }
      console.error('Login error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout>
      <Card title={<Title level={3} style={{ textAlign: 'center', marginBottom: 0 }}>Secure Code Platform Login</Title>} style={{ boxShadow: '0 4px 8px rgba(0,0,0,0.1)' }}>
        {error && <Alert message={error} type="error" showIcon closable style={{ marginBottom: 20 }} onClose={() => setError(null)} />}
        <Form
          name="login"
          initialValues={{ remember: true }}
          onFinish={onFinish}
          size="large"
        >
          <Form.Item
            name="username" // This will be the email
            rules={[{ required: true, message: 'Please input your Email!' }, { type: 'email', message: 'Please enter a valid email!' }]}
          >
            <Input prefix={<UserOutlined />} placeholder="Email" />
          </Form.Item>
          <Form.Item
            name="password"
            rules={[{ required: true, message: 'Please input your Password!' }]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="Password" />
          </Form.Item>
          <Form.Item>
            <Form.Item name="remember" valuePropName="checked" noStyle>
              <Checkbox>Remember me</Checkbox>
            </Form.Item>
            <a style={{ float: 'right' }} href="/forgot-password"> {/* Placeholder */}
              Forgot password?
            </a>
          </Form.Item>
          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} block>
              Log in
            </Button>
          </Form.Item>
          Or <Link to="/register">register now!</Link>
        </Form>
      </Card>
    </AuthLayout>
  );
};

export default LoginPage;