// secure-code-ui/src/features/authentication/components/RegisterPage.tsx
import { LockOutlined, MailOutlined } from "@ant-design/icons";
import { Button, Col, Form, Input, message, Row, Typography } from "antd";
import { AxiosError } from "axios";
import React from "react";
import { Link, useNavigate } from "react-router-dom"; // Added useNavigate
import { useAuth } from "../../../shared/hooks/useAuth";
import { type UserRegisterData } from "../../../shared/types/api";

const { Title, Paragraph } = Typography;

const RegisterPage: React.FC = () => {
  const { register } = useAuth();
  const navigate = useNavigate(); // Added useNavigate
  const [form] = Form.useForm();
  const [loading, setLoading] = React.useState(false);
  // Removed local error and successMessage states

  const onFinish = async (values: UserRegisterData) => {
    setLoading(true);
    // setError(null); // Removed
    // setSuccessMessage(null); // Removed
    try {
      await register(values);
      message.success(
        "Registration successful! Redirecting to login...",
      );
      setTimeout(() => {
        navigate("/login");
      }, 3000); // 3-second delay
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
      message.error(errorMessage); // Use message.error
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
    message.error("Please correct the highlighted errors."); // Use message.error
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
          {/* Removed Alert components for error and successMessage */}
          {/* Form is no longer conditionally rendered based on successMessage */}
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
          {/* Removed conditional rendering for success button, navigation is now automatic */}
        </div>
      </Col>
    </Row>
  );
};

export default RegisterPage;
