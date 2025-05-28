// secure-code-ui/src/pages/dashboard/SettingsPage.tsx
import { Card, Divider, Typography } from "antd";
import React from "react";

const { Title, Paragraph } = Typography;

const SettingsPage: React.FC = () => {
  return (
    <Card>
      <Title level={2}>Settings</Title>
      <Paragraph>
        This is the placeholder for the Application Settings page. You will be
        able to configure various aspects of the platform here.
      </Paragraph>
      <Divider />
      <Title level={4}>Notification Settings</Title>
      <Paragraph>Configure your notification preferences.</Paragraph>
      {/* Add more placeholder sections as needed */}
      <Divider />
      <Title level={4}>Account Settings</Title>
      <Paragraph>
        Manage your account preferences (e.g., change password - link to a
        dedicated flow).
      </Paragraph>
    </Card>
  );
};

export default SettingsPage; // <-- Make sure to have this default export
