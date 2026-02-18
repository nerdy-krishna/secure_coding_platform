import { Card, Divider, Typography, Select, message, Spin, Row, Col } from "antd";
import React, { useEffect, useState } from "react";
import { logService } from "../../shared/api/logService";


const { Title, Paragraph, Text } = Typography;

const SettingsPage: React.FC = () => {
  const [logLevel, setLogLevel] = useState<string>("INFO");
  const [loadingLogs, setLoadingLogs] = useState<boolean>(false);

  useEffect(() => {
    fetchLogLevel();
  }, []);

  const fetchLogLevel = async () => {
    setLoadingLogs(true);
    try {
      const data = await logService.getLogLevel();
      setLogLevel(data.level);
    } catch (error) {
      console.error("Failed to fetch log level:", error);
      message.error("Failed to fetch current log level.");
    } finally {
      setLoadingLogs(false);
    }
  };

  const handleLogLevelChange = async (value: string) => {
    setLoadingLogs(true);
    try {
      // Cast to the specific union type required by setLogLevel
      await logService.setLogLevel(value as "DEBUG" | "INFO" | "WARNING" | "ERROR");
      setLogLevel(value);
      message.success(`System log level set to ${value}`);
    } catch (error) {
      console.error("Failed to set log level:", error);
      message.error("Failed to update log level.");
    } finally {
      setLoadingLogs(false);
    }
  };

  return (
    <Card>
    <Title level= { 2} > Settings </Title>
    <Paragraph>
        This is the placeholder for the Application Settings page.You will be
        able to configure various aspects of the platform here.
      </Paragraph>
  {/* System Logs Section */ }
  <Divider />
    < Title level = { 4} > System Logs </Title>
      <Paragraph>
        Control the verbosity of the backend application logs.
        < br />
    <Text type="secondary" >
      Select < strong > DEBUG </strong> to see full LLM prompts and responses (useful for debugging).
  Select < strong > INFO </strong> for standard operation.
    </Text>
    </Paragraph>
    < Row >
    <Col xs={ 24 } sm = { 12} md = { 8} >
      <Spin spinning={ loadingLogs }>
        <Select
                    value={ logLevel }
  style = {{ width: "100%" }
}
onChange = { handleLogLevelChange }
options = {
  [
  { value: 'DEBUG', label: 'DEBUG (Verbose - Includes Prompts)' },
  { value: 'INFO', label: 'INFO (Standard)' },
  { value: 'WARNING', label: 'WARNING (Errors Only)' },
                    ]}
  />
  </Spin>
  </Col>
  </Row>

{/* Removed Display Settings Section */ }
<Divider />
  < Title level = { 4} > Notification Settings </Title>
    < Paragraph > Configure your notification preferences.</Paragraph>
{/* Add more placeholder sections as needed */ }
<Divider />
  < Title level = { 4} > Account Settings </Title>
    <Paragraph>
        Manage your account preferences(e.g., change password - link to a
        dedicated flow).
      </Paragraph>
  </Card>
  );
};

export default SettingsPage;
