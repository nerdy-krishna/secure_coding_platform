// secure-code-ui/src/features/authentication/components/ForgotPasswordPage.tsx
import React, { useState } from "react";
import { Form, Input, Button, Typography, message, Row, Col } from "antd";
import { UserOutlined } from "@ant-design/icons";
import { authService } from "../../../shared/api/authService";
import { Link } from "react-router-dom";

const { Title, Paragraph } = Typography;

const ForgotPasswordPage: React.FC = () => {
    const [loading, setLoading] = useState(false);
    const [success, setSuccess] = useState(false);

    const onFinish = async (values: { email: string }) => {
        setLoading(true);
        try {
            await authService.forgotPassword(values.email);
            setSuccess(true);
            message.success("Password reset email sent (if an account exists).");
        } catch (error) {
            console.error("Forgot password failed:", error);
            message.error("Failed to request password reset.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <Row justify= "center" align = "middle" style = {{ minHeight: "100vh", background: "#f0f2f5" }
}>
    <Col xs={ 22 } sm = { 16} md = { 12} lg = { 8} xl = { 6} >
        <div style={ { background: "#fff", padding: "40px", borderRadius: "8px", boxShadow: "0 4px 12px rgba(0,0,0,0.1)" } }>
            <Title level={ 2 } style = {{ textAlign: "center", marginBottom: "30px" }}> Forgot Password </Title>
{
    success ? (
        <div style= {{ textAlign: "center" }
}>
    <Paragraph>If an account exists for that email, a password reset link has been sent.</Paragraph>
        < Link to = "/login" > Return to login </Link>
            </div>
                    ) : (
    <Form name= "forgot-password" onFinish = { onFinish } layout = "vertical" >
        <Paragraph style={ { textAlign: "center", marginBottom: "20px" } }> Enter your email address and we will send you a link to reset your password.</Paragraph>
            < Form.Item name = "email" rules = { [{ required: true, type: "email", message: "Please enter a valid email address!" }]} >
                <Input prefix={
                    <UserOutlined />} placeholder="Email Address" size="large" / >
                    </Form.Item>
                    < Form.Item >
                    <Button type="primary" htmlType = "submit" loading = { loading } size = "large" style = {{ width: "100%" }
}>
    Send Reset Link
        </Button>
        </Form.Item>
        < div style = {{ textAlign: "center" }}>
            <Link to="/login" > Back to Login </Link>
                </div>
                </Form>
                    )}
</div>
    </Col>
    </Row>
    );
};

export default ForgotPasswordPage;
