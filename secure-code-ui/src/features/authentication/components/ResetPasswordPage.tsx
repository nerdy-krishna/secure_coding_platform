// secure-code-ui/src/features/authentication/components/ResetPasswordPage.tsx
import React, { useState, useEffect } from "react";
import { Form, Input, Button, Typography, message } from "antd";
import { LockOutlined } from "@ant-design/icons";
import { authService } from "../../../shared/api/authService";
import { useNavigate, useLocation } from "react-router-dom";

const { Title, Paragraph } = Typography;

const ResetPasswordPage: React.FC = () => {
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();
    const location = useLocation();
    const searchParams = new URLSearchParams(location.search);
    const token = searchParams.get("token");

    useEffect(() => {
        if (!token) {
            message.error("Invalid or missing reset token.");
        }
    }, [token]);

    const onFinish = async (values: any) => {
        if (!token) {
            message.error("No token provided.");
            return;
        }
        setLoading(true);
        try {
            await authService.resetPassword(token, values.password);
            message.success("Password secured! You can now log in.");
            navigate("/login");
        } catch (error) {
            console.error("Reset password failed:", error);
            message.error("Failed to reset password. The link might be expired.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style= {{ background: "#fff", padding: "40px", borderRadius: "8px", boxShadow: "0 4px 12px rgba(0,0,0,0.1)" }
}>
    <Title level={ 2 } style = {{ textAlign: "center", marginBottom: "30px" }}> Set New Password </Title>
        < Form name = "reset-password" onFinish = { onFinish } layout = "vertical" >
            <Paragraph style={ { textAlign: "center", marginBottom: "20px" } }> Please enter your new password below.</Paragraph>
                < Form.Item name = "password" rules = { [{ required: true, message: "Please enter your new password!" }]} >
                    <Input.Password prefix={
    <LockOutlined />} placeholder="New Password" size="large" / >
        </Form.Item>
        < Form.Item name = "confirm" dependencies = { ['password']} rules = {
            [
                { required: true, message: "Please confirm your password!" },
                ({ getFieldValue }) => ({
                    validator(_, value) {
                        if (!value || getFieldValue('password') === value) {
                            return Promise.resolve();
                        }
                        return Promise.reject(new Error('The two passwords do not match!'));
                    },
                })
            ]} >
            <Input.Password prefix={
        <LockOutlined />} placeholder="Confirm Password" size="large" / >
            </Form.Item>
            < Form.Item >
            <Button type="primary" htmlType = "submit" loading = { loading } size = "large" style = {{ width: "100%" }
    } disabled = {!token
}>
    Reset Password
        </Button>
        </Form.Item>
        </Form>
        </div>
    );
};

export default ResetPasswordPage;
