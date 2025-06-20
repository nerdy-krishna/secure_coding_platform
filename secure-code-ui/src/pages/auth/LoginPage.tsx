// secure-code-ui/src/pages/auth/LoginPage.tsx
import { LockOutlined, UserOutlined } from "@ant-design/icons";
import {
  Button,
  Checkbox,
  Col,
  Form,
  Input,
  message, // Added message
  Row,
  Typography,
} from "antd";
import React from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../../hooks/useAuth";
import { type UserLoginData } from "../../types/api";

const { Title } = Typography;

const LoginPage: React.FC = () => {
  const {
    login,
    error: authError,
    clearError,
    isLoading: authLoading,
  } = useAuth();
  const navigate = useNavigate();
  const [form] = Form.useForm();

  // Removed useEffect for clearError

  const onFinish = async (values: UserLoginData) => {
    try {
      await login(values);
      navigate("/dashboard");
    } catch (err: any) { // Catch specific error types if known, else 'any' or 'unknown'
      console.error("LoginPage: Login attempt failed:", err);
      let errorMessage = "Login failed. Please check your credentials and try again.";
      if (err && err.message) {
        // Prefer a message from the error object if available and user-friendly
        // This depends on what `useAuth().login` throws.
        // For now, we use a generic one, but if `authError` from useAuth is reliable,
        // we could potentially use that, or err.response.data.detail for Axios errors.
        // Example: if (err.response?.data?.detail) errorMessage = err.response.data.detail;
      }
      // If authError from useAuth hook is updated reliably by the login function, use it.
      // Otherwise, use the error caught here.
      // For now, let's assume authError from the hook is the source of truth if set.
      if (authError) {
        message.error(authError);
      } else {
        message.error(errorMessage);
      }
    }
  };

  interface AntDValidationError {
    values: UserLoginData;
    errorFields: { name: (string | number)[]; errors: string[] }[];
    outOfDate: boolean;
  }

  const onFinishFailed = (errorInfo: AntDValidationError) => {
    console.log("LoginPage: Form validation failed:", errorInfo);
  };

  return (
    <Row
      justify="center"
      align="middle"
      style={{ minHeight: "100vh", background: "#f0f2f5" }}
    >
      {/* Updated Col props for width adjustment */}
      <Col xs={22} sm={16} md={12} lg={24} xl={24}>
        {" "}
        {/* <-- UPDATED HERE */}
        <div
          style={{
            background: "#fff",
            padding: "40px", // You can adjust padding if needed too
            borderRadius: "8px",
            boxShadow: "0 4px 12px rgba(0,0,0,0.1)",
          }}
        >
          <Title
            level={2}
            style={{ textAlign: "center", marginBottom: "30px" }}
          >
            Login
          </Title>
          {/* Alert removed, messages will be shown via antd message API */}
          <Form
            form={form}
            name="login"
            initialValues={{ remember: true }}
            onFinish={onFinish}
            onFinishFailed={onFinishFailed}
            layout="vertical"
          >
            <Form.Item
              name="username"
              label="Username or Email"
              rules={[
                {
                  required: true,
                  message: "Please input your Username or Email!",
                },
              ]}
            >
              <Input
                prefix={<UserOutlined />}
                placeholder="Username or Email"
              />
            </Form.Item>

            <Form.Item
              name="password"
              label="Password"
              rules={[
                { required: true, message: "Please input your Password!" },
              ]}
            >
              <Input.Password
                prefix={<LockOutlined />}
                placeholder="Password"
              />
            </Form.Item>

            <Form.Item name="remember" valuePropName="checked">
              <Checkbox>Remember me</Checkbox>
            </Form.Item>

            <Form.Item>
              <Button
                type="primary"
                htmlType="submit"
                loading={authLoading}
                style={{ width: "100%" }}
              >
                Log in
              </Button>
            </Form.Item>
            <div style={{ textAlign: "center" }}>
              Or <Link to="/register">register now!</Link>
              {/* <br />
              <Link to="/forgot-password">Forgot password?</Link> */}
            </div>
          </Form>
        </div>
      </Col>
    </Row>
  );
};

export default LoginPage;
