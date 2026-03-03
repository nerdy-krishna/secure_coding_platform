import React, { useState, useEffect } from "react";
import {
  Table,
  Button,
  Modal,
  Form,
  Input,
  Switch,
  message,
  Popconfirm,
  Typography,
  Divider,
  Row,
  Col,
  Select,
  Spin,
  Checkbox,
  List,
} from "antd";
import { PlusOutlined, EditOutlined, DeleteOutlined } from "@ant-design/icons";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import apiClient from "../../shared/api/apiClient";
import { logService } from "../../shared/api/logService";
import { systemConfigService } from "../../shared/api/systemConfigService";

const { Text, Title, Paragraph } = Typography;

interface SystemConfig {
  key: string;
  value: any;
  description: string;
  is_secret: boolean;
  encrypted: boolean;
  created_at: string;
  updated_at: string;
}

const SystemConfigTab: React.FC = () => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();

  // Settings State
  const [logLevel, setLogLevel] = useState<string>("INFO");
  const [loadingLogs, setLoadingLogs] = useState<boolean>(false);
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
      try {
        const logData = await logService.getLogLevel();
        setLogLevel(logData.level);
      } catch (e) {
        console.error("Failed to fetch log level", e);
      }

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
      queryClient.invalidateQueries({ queryKey: ["system-configs"] });
    } catch (error) {
      console.error("Failed to update CORS setting:", error);
      setCorsEnabled(!newValue);
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
      await systemConfigService.update("security.allowed_origins", { value: { origins: newOrigins } });
      message.success("Allowed origins updated");
      queryClient.invalidateQueries({ queryKey: ["system-configs"] });
    } catch (error) {
      console.error("Failed to update origins:", error);
      message.error("Failed to update allowed origins.");
      fetchConfigs();
    } finally {
      setLoadingCors(false);
    }
  };

  const { data: configs, isLoading } = useQuery({
    queryKey: ["system-configs"],
    queryFn: async () => {
      const res = await apiClient.get<SystemConfig[]>("/admin/system-config/");
      return res.data;
    },
  });

  const createMutation = useMutation({
    mutationFn: (values: any) =>
      apiClient.put(`/admin/system-config/${values.key}`, values),
    onSuccess: () => {
      message.success("Configuration saved successfully");
      setIsModalOpen(false);
      form.resetFields();
      queryClient.invalidateQueries({ queryKey: ["system-configs"] });
      fetchConfigs(); // Refresh local settings states if updated via table
    },
    onError: () => message.error("Failed to save configuration"),
  });

  const deleteMutation = useMutation({
    mutationFn: (key: string) =>
      apiClient.delete(`/admin/system-config/${key}`),
    onSuccess: () => {
      message.success("Configuration deleted successfully");
      queryClient.invalidateQueries({ queryKey: ["system-configs"] });
    },
    onError: () => message.error("Failed to delete configuration"),
  });

  const handleAdd = () => {
    setEditingKey(null);
    form.resetFields();
    setIsModalOpen(true);
  };

  const handleEdit = (record: SystemConfig) => {
    setEditingKey(record.key);
    // Clean deep clone to avoid mutating original
    const values = { ...record };
    if (typeof values.value === "object") {
      values.value = JSON.stringify(values.value, null, 2);
    }
    form.setFieldsValue(values);
    setIsModalOpen(true);
  };

  const handleDelete = (key: string) => {
    deleteMutation.mutate(key);
  };

  const handleOk = () => {
    form.validateFields().then((values) => {
      try {
        // Try to parse JSON if it's a string, else use as is (if input as text)
        // For simplicity, we assume generic JSON input is text area
        const parsedValue = JSON.parse(values.value);
        values.value = parsedValue;

        createMutation.mutate(values);
      } catch (e) {
        message.error("Invalid JSON format for Value");
      }
    });
  };

  const columns = [
    {
      title: "Key",
      dataIndex: "key",
      key: "key",
      render: (text: string) => <Text strong > { text } </Text>,
    },
    {
      title: "Value",
      dataIndex: "value",
      key: "value",
      render: (val: any, record: SystemConfig) => {
        if (record.is_secret) return <Text type="secondary" >******** </Text>;
        if (typeof val === "object")
          return <Text code > { JSON.stringify(val) } </Text>;
        return <Text>{ String(val) } </Text>;
      },
    },
    {
      title: "Description",
      dataIndex: "description",
      key: "description",
    },
    {
      title: "Secret",
      dataIndex: "is_secret",
      key: "is_secret",
      render: (val: boolean) => (val ? "Yes" : "No"),
    },
    {
      title: "Actions",
      key: "actions",
      render: (_: any, record: SystemConfig) => (
        <div style= {{ display: "flex", gap: 8 }}>
          <Button
            icon={ <EditOutlined /> }
size = "small"
onClick = {() => handleEdit(record)}
          />
  < Popconfirm
title = "Delete setting"
description = "Are you sure you want to delete this setting?"
onConfirm = {() => handleDelete(record.key)}
okText = "Yes"
cancelText = "No"
  >
  <Button
              icon={ <DeleteOutlined /> }
size = "small"
danger
loading = { deleteMutation.isPending }
  />
  </Popconfirm>
  </div>
      ),
    },
  ];

return (
  <div>
  <Title level= { 2} > Platform Settings </Title>
    <Paragraph>
        Configure core system behavior, global variables, and environmental settings.
      </Paragraph>

{/* System Logs Section */ }
<Divider />
  < Title level = { 4} > System Logs </Title>
    <Paragraph>
        Control the verbosity of the backend application logs.< br />
  <Text type="secondary" >
    Select <strong>DEBUG</strong> to see full LLM prompts and responses (useful for debugging). Select <strong>INFO</strong> for standard operation.
          </Text>
      </Paragraph>
      < Row >
      <Col xs= { 24} sm = { 12} md = { 8} >
        <Spin spinning={ loadingLogs }>
          <Select
              value={ logLevel }
style = {{ width: "100%" }}
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
        Manage Cross - Origin Resource Sharing(CORS) settings.< br />
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
  <Title level={ 4 }> Global Variables </Title>
    < div
style = {{
  marginBottom: 16,
    display: "flex",
      justifyContent: "space-between",
        alignItems: "center"
}}
      >
  <Paragraph style={ { margin: 0 } }>
    Manage lower - level configuration records.
        </Paragraph>
      < Button type = "primary" icon = {< PlusOutlined />} onClick = { handleAdd } >
        Add Setting
          </Button>
          </div>
          < Table
columns = { columns }
dataSource = { configs }
rowKey = "key"
loading = { isLoading }
pagination = {{ pageSize: 10 }}
      />

  < Modal
title = { editingKey? "Edit Setting": "Add Setting" }
open = { isModalOpen }
onOk = { handleOk }
onCancel = {() => setIsModalOpen(false)}
confirmLoading = { createMutation.isPending }
  >
  <Form form={ form } layout = "vertical" >
    <Form.Item name="key" label = "Key" rules = { [{ required: true }]} >
      <Input
              disabled={ !!editingKey }
placeholder = "e.g. GLOBAL_ALERT_MESSAGE"
  />
  </Form.Item>
  < Form.Item
name = "value"
label = "Value (JSON)"
rules = { [{ required: true }]}
  >
  <Input.TextArea
              rows={ 4 }
placeholder = '{"message": "Maintenance Mode"}'
  />
  </Form.Item>
  < Form.Item name = "description" label = "Description" >
    <Input placeholder="Short description of this setting" />
      </Form.Item>
      < Form.Item
name = "is_secret"
label = "Is Secret?"
valuePropName = "checked"
  >
  <Switch />
  </Form.Item>
  </Form>
  </Modal>
  </div>
  );
};

export default SystemConfigTab;
