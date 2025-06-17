// secure-code-ui/src/pages/dashboard/SettingsPage.tsx
import { Card, Divider, Radio, RadioChangeEvent, Space, Typography } from "antd";
import React, { useEffect, useState } from "react";

const { Title, Paragraph } = Typography;

export type TimeDisplayPreference = "local" | "utc";
const TIME_DISPLAY_PREFERENCE_KEY = "timeDisplayPreference";

const SettingsPage: React.FC = () => {
  const [timePreference, setTimePreference] = useState<TimeDisplayPreference>("local");

  useEffect(() => {
    const storedPreference = localStorage.getItem(TIME_DISPLAY_PREFERENCE_KEY) as TimeDisplayPreference | null;
    if (storedPreference) {
      setTimePreference(storedPreference);
    }
  }, []);

  const handleTimePreferenceChange = (e: RadioChangeEvent) => {
    const newPreference = e.target.value as TimeDisplayPreference;
    setTimePreference(newPreference);
    localStorage.setItem(TIME_DISPLAY_PREFERENCE_KEY, newPreference);
  };

  return (
    <Card>
      <Title level={2}>Settings</Title>
      <Paragraph>
        This is the placeholder for the Application Settings page. You will be
        able to configure various aspects of the platform here.
      </Paragraph>
      <Divider />
      <Title level={4}>Display Settings</Title>
      <Space direction="vertical">
        <Paragraph style={{ marginBottom: 0 }}>Date & Time Display:</Paragraph>
        <Radio.Group onChange={handleTimePreferenceChange} value={timePreference}>
          <Radio value="local">Local Time</Radio>
          <Radio value="utc">UTC Time</Radio>
        </Radio.Group>
      </Space>
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
