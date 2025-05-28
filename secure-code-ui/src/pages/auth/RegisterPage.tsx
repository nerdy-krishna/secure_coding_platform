import { LockOutlined, MailOutlined } from "@ant-design/icons";
import { Alert, Button, Col, Form, Input, Row, Typography } from "antd";
import { AxiosError } from "axios";
import React from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../hooks/useAuth";
import { type UserRegisterData } from "../../types/api";

const { Title, Paragraph } = Typography;

const RegisterPage: React.FC = () => {
  const { register } = useAuth();
  const [form] = Form.useForm();
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [successMessage, setSuccessMessage] = React.useState<string | null>(
    null,
  );

  const onFinish = async (values: UserRegisterData) => {
    setLoading(true);
    setError(null);
    setSuccessMessage(null);
    try {
      await register(values);
      setSuccessMessage(
        "Registration successful! Please check your email to verify your account.",
      );
    } catch (err) {
      let errorMessage = "Registration failed. Please try again.";
      if (err instanceof AxiosError && err.response) {
        const responseData = err.response.data as {
          detail?: string | { msg: string; loc: (string | number)[] }[];
        };

        if (typeof responseData.detail === "string") {
          switch (responseData.detail) {
            case "REGISTER_USER_ALREADY_EXISTS":
              errorMessage =
                "This email is already registered. Please try logging in.";
              break;
            case "REGISTER_INVALID_PASSWORD":
              errorMessage =
                "Password does not meet complexity requirements. It should be at least 8 characters long and contain a mix of uppercase, lowercase, digits, and special characters.";
              break;
            default:
              errorMessage = responseData.detail;
          }
        } else if (Array.isArray(responseData.detail)) {
          const pydanticErrors = responseData.detail
            .map((e) => `${e.loc.join(".")} - ${e.msg}`)
            .join("; ");
          errorMessage = `Validation errors: ${pydanticErrors}`;
        }
      } else if (err instanceof Error) {
        errorMessage = err.message;
      }
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  interface AntDValidationError {
    values: UserRegisterData;
    errorFields: { name: (string | number)[]; errors: string[] }[];
    outOfDate: boolean;
  }

  const onFinishFailed = (errorInfo: AntDValidationError) => {
    console.log("Failed:", errorInfo);
    setError("Please correct the highlighted errors.");
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
            style={{ textAlign: "center", marginBottom: "10px" }}
          >
            Create Account
          </Title>
          <Paragraph style={{ textAlign: "center", marginBottom: "30px" }}>
            Join the Secure Code Platform.
          </Paragraph>
          {error && (
            <Alert
              message={error}
              type="error"
              showIcon
              style={{ marginBottom: "20px" }}
            />
          )}
          {successMessage && (
            <Alert
              message={successMessage}
              type="success"
              showIcon
              style={{ marginBottom: "20px" }}
            />
          )}
          {!successMessage && (
            <Form
              form={form}
              name="register"
              onFinish={onFinish}
              onFinishFailed={onFinishFailed}
              layout="vertical"
              scrollToFirstError
            >
              <Form.Item
                name="email"
                label="Email"
                rules={[
                  { required: true, message: "Please input your Email!" },
                  { type: "email", message: "The input is not a valid Email!" },
                ]}
              >
                <Input prefix={<MailOutlined />} placeholder="Email" />
              </Form.Item>

              <Form.Item
                name="password"
                label="Password"
                rules={[
                  { required: true, message: "Please input your Password!" },
                  {
                    min: 8,
                    message: "Password must be at least 8 characters long.",
                  },
                ]}
                hasFeedback
              >
                <Input.Password
                  prefix={<LockOutlined />}
                  placeholder="Password"
                />
              </Form.Item>

              <Form.Item
                name="confirm"
                label="Confirm Password"
                dependencies={["password"]}
                hasFeedback
                rules={[
                  { required: true, message: "Please confirm your Password!" },
                  ({ getFieldValue }) => ({
                    validator(_, value) {
                      if (!value || getFieldValue("password") === value) {
                        return Promise.resolve();
                      }
                      return Promise.reject(
                        new Error(
                          "The two passwords that you entered do not match!",
                        ),
                      );
                    },
                  }),
                ]}
              >
                <Input.Password
                  prefix={<LockOutlined />}
                  placeholder="Confirm Password"
                />
              </Form.Item>

              <Form.Item>
                <Button
                  type="primary"
                  htmlType="submit"
                  loading={loading}
                  style={{ width: "100%" }}
                >
                  Register
                </Button>
              </Form.Item>
              <div style={{ textAlign: "center" }}>
                Already have an account? <Link to="/login">Log in</Link>
              </div>
            </Form>
          )}
          {successMessage && (
            <div style={{ textAlign: "center", marginTop: "20px" }}>
              <Link to="/login">
                <Button type="primary">Proceed to Login</Button>
              </Link>
            </div>
          )}
        </div>
      </Col>
    </Row>
  );
};

export default RegisterPage;
