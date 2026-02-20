// secure-code-ui/src/pages/account/SettingsPage.tsx
import { Card, Divider, Typography, Select, message, Spin, Row, Col, Checkbox, Input, Button, List } from "antd";
import React, { useEffect, useState } from "react";
import { logService } from "../../shared/api/logService";
import { systemConfigService } from "../../shared/api/systemConfigService";

const { Title, Paragraph, Text } = Typography;

const SettingsPage: React.FC = () => {
  const [logLevel, setLogLevel] = useState<string>("INFO");
  const [loadingLogs, setLoadingLogs] = useState<boolean>(false);

  // CORS State
  const [loadingCors, setLoadingCors] = useState<boolean>(false);
  const [corsEnabled, setCorsEnabled] = useState<boolean>(false);
  const [allowedOrigins, setAllowedOrigins] = useState<string[]>([]);
  const [originInput, setOriginInput] = useState<string>("");

  useEffect(() => {
    fetchConfigs();
  }, []);

  const fetchConfigs = async () => {
    setLoadingLogs(true);
    setLoadingCors(true);
    try {
      // Fetch Log Level
      try {
        const logData = await logService.getLogLevel();
        setLogLevel(logData.level);
      } catch (e) {
        console.error("Failed to fetch log level", e);
      }

      // Fetch System Configs
      try {
        const allConfigs = await systemConfigService.getAll();
        const corsEnabledConfig = allConfigs.find(c => c.key === "security.cors_enabled");
        const originsConfig = allConfigs.find(c => c.key === "security.allowed_origins");

        if (corsEnabledConfig && corsEnabledConfig.value !== undefined) {
          setCorsEnabled(Boolean(corsEnabledConfig.value));
        }

        if (originsConfig && originsConfig.value && originsConfig.value.origins) {
          setAllowedOrigins(originsConfig.value.origins);
        }
      } catch (e) {
        console.error("Failed to fetch system configs", e);
      }

    } catch (error) {
      console.error("Failed to fetch settings:", error);
      message.error("Failed to fetch settings.");
    } finally {
      setLoadingLogs(false);
      setLoadingCors(false);
    }
  };

  const handleLogLevelChange = async (value: string) => {
    setLoadingLogs(true);
    try {
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

  const handleCorsToggle = async (e: any) => {
    const newValue = e.target.checked;
    setLoadingCors(true);
    try {
      setCorsEnabled(newValue);
      await systemConfigService.update("security.cors_enabled", { value: newValue });
      message.success(`CORS ${newValue ? "Enabled" : "Disabled"}`);
    } catch (error) {
      console.error("Failed to update CORS setting:", error);
      setCorsEnabled(!newValue); // Revert
      message.error("Failed to update CORS setting.");
    } finally {
      setLoadingCors(false);
    }
  };

  const addOrigin = async () => {
    if (!originInput) return;
    if (allowedOrigins.includes(originInput)) {
      message.warning("Origin already exists");
      return;
    }

    const newOrigins = [...allowedOrigins, originInput];
    updateOrigins(newOrigins);
    setOriginInput("");
  };

  const removeOrigin = async (origin: string) => {
    const newOrigins = allowedOrigins.filter(o => o !== origin);
    updateOrigins(newOrigins);
  };

  const updateOrigins = async (newOrigins: string[]) => {
    setLoadingCors(true);
    try {
      setAllowedOrigins(newOrigins);
      // The backend expects value to be a JSON object with "origins" key for this specific config
      // based on main.py logic: config.value["origins"]
      await systemConfigService.update("security.allowed_origins", { value: { origins: newOrigins } });
      message.success("Allowed origins updated");
    } catch (error) {
      console.error("Failed to update origins:", error);
      message.error("Failed to update allowed origins.");
      // Re-fetch to revert to server state
      fetchConfigs();
    } finally {
      setLoadingCors(false);
    }
  };

  return (
    <Card>
    <Title level= { 2} > Settings </Title>
    <Paragraph>
                Configure platform settings.
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

{/* CORS Configuration Section */ }
<Divider />
  < Title level = { 4} > CORS Configuration </Title>
    <Paragraph>
                Manage Cross - Origin Resource Sharing(CORS) settings.
                < br />
  <Text type="secondary" >
    Enable strict CORS policies to restrict API access to specific domains.
                </Text>
      </Paragraph>

      < Spin spinning = { loadingCors } >
        <div style={ { marginBottom: 16 } }>
          <Checkbox checked={ corsEnabled } onChange = { handleCorsToggle } >
            Enable CORS Configuration
              </Checkbox>
              < div style = {{ marginTop: 8, color: '#888', fontSize: '12px' }}>
                If disabled, allow blocked(or strict same - origin depending on middleware logic).
                    </div>
                  </div>

{
  corsEnabled && (
    <div style={ { paddingLeft: 20, borderLeft: '2px solid #ddd' } }>
      <Text strong > Allowed Origins </Text>
        < div style = {{ display: "flex", gap: "8px", marginTop: "8px", marginBottom: "16px", maxWidth: "500px" }
}>
  <Input
                                value={ originInput }
onChange = {(e) => setOriginInput(e.target.value)}
placeholder = "https://my-domain.com"
onPressEnter = { addOrigin }
  />
  <Button onClick={ addOrigin } type = "primary" > Add </Button>
    </div>

    < List
size = "small"
bordered
dataSource = { allowedOrigins }
style = {{ maxWidth: "500px" }}
renderItem = {(item) => (
  <List.Item
                                    actions= { [<Button type= "link" danger onClick={() => removeOrigin(item) } > Remove </Button>]}
                                >
  { item }
  </List.Item>
                            )}
                        />
  </div>
                )}
</Spin>

  < Divider />
  <Title level={ 4 }> Account Settings </Title>
    <Paragraph>
                Manage your account preferences.
            </Paragraph>
  </Card>
    );
};
export default SettingsPage;
