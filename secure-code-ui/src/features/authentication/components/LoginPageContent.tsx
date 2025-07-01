// secure-code-ui/src/features/authentication/components/LoginPageContent.tsx

import { LockOutlined, UserOutlined } from "@ant-design/icons";
import {
  Button,
  Checkbox,
  Col,
  Form,
  Input,
  message,
  Row,
  Typography,
} from "antd";
import React from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../../shared/hooks/useAuth";
import { type UserLoginData } from "../../../shared/types/api";

const { Title } = Typography;

const LoginPageContent: React.FC = () => {
  const {
    login,
    error: authError,
    isLoading: authLoading,
  } = useAuth();
  
  const [form] = Form.useForm();

  const onFinish = async (values: UserLoginData) => {
    try {
      await login(values);
      
    } catch (err: unknown) {
      
      console.error("LoginPage: Login attempt failed:", err);
      
      if (!authError) {
        message.error("Login failed. Please check your credentials and try again.");
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
      <Col xs={22} sm={16} md={12} lg={24} xl={24}>
        <div
          style={{
            background: "#fff",
            padding: "40px",
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
            </div>
          </Form>
        </div>
      </Col>
    </Row>
  );
};

export default LoginPageContent;