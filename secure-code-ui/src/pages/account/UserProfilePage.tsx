// src/app/pages/dashboard/UserProfilePage.tsx
import { EditOutlined, UserOutlined } from "@ant-design/icons";
import { Avatar, Button, Card, Descriptions, Divider, Typography } from "antd";
import React from "react";
import { useAuth } from "../../shared/hooks/useAuth";

const { Title, Text } = Typography; // Removed Paragraph as it wasn't used directly here

const UserProfilePage: React.FC = () => {
  const { user } = useAuth(); // Get user information from AuthContext

  return (
    <Card>
      <div style={{ display: "flex", alignItems: "center", marginBottom: 24 }}>
        {/* Removed src={user?.avatar_url} for now */}
        <Avatar size={64} icon={<UserOutlined />} />
        <div style={{ marginLeft: 20 }}>
          <Title level={2} style={{ marginBottom: 0 }}>
            {/* You could add a name field to UserRead in the future too */}
            {user ? user.email : "User Profile"}
          </Title>
          <Text type="secondary">
            {user ? `User ID: ${user.id}` : "Loading user data..."}
          </Text>
        </div>
        <Button
          type="primary"
          icon={<EditOutlined />}
          style={{ marginLeft: "auto" }}
          disabled
        >
          {" "}
          {/* Disabled for now */}
          Edit Profile
        </Button>
      </div>
      <Divider />
      <Title level={4}>Account Details</Title>
      {user ? (
        <Descriptions bordered column={1} layout="horizontal">
          <Descriptions.Item label="Email">{user.email}</Descriptions.Item>
          <Descriptions.Item label="User ID">{user.id}</Descriptions.Item>
          <Descriptions.Item label="Active">
            {user.is_active ? "Yes" : "No"}
          </Descriptions.Item>
          <Descriptions.Item label="Verified">
            {user.is_verified ? "Yes" : "No"}
          </Descriptions.Item>
          <Descriptions.Item label="Superuser">
            {user.is_superuser ? "Yes" : "No"}
          </Descriptions.Item>
        </Descriptions>
      ) : (
        <Text>Loading user details or user not available.</Text>
      )}
      {/* You can add more sections like 'Activity', 'Security Settings for User', etc. later */}
    </Card>
  );
};

export default UserProfilePage;
