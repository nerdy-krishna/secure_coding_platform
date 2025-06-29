// src/app/app/pages/dashboard/SettingsPage.tsx
import { Card, Divider, Typography } from "antd";
import React from "react";

const { Title, Paragraph } = Typography;

// Removed TimeDisplayPreference type and TIME_DISPLAY_PREFERENCE_KEY

const SettingsPage: React.FC = () => {
  // Removed useState, useEffect, and handleTimePreferenceChange related to timePreference

  return (
    <Card>
      <Title level={2}>Settings</Title>
      <Paragraph>
        This is the placeholder for the Application Settings page. You will be
        able to configure various aspects of the platform here.
      </Paragraph>
      {/* Removed Display Settings Section */}
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

export default SettingsPage;
