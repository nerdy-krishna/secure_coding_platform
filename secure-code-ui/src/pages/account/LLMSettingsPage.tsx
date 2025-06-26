import {
  ClearOutlined,
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Button,
  Card,
  Col,
  Form,
  Input,
  InputNumber,
  message,
  Popconfirm,
  Row,
  Select,
  Space,
  Table,
  Tag,
  Typography,
  type TableProps,
} from "antd";
import type { RuleObject } from "antd/es/form";
import { AxiosError } from "axios";
import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  llmConfigService,
  type LLMConfigurationUpdate,
} from "../../services/llmConfigService";
import type { LLMConfiguration, LLMConfigurationCreate } from "../../types/api";

const { Title, Paragraph, Text } = Typography;
const { Option } = Select;

const LLM_PROVIDERS = ["openai", "google", "anthropic"];

const LLMSettingsPage: React.FC = () => {
  const [form] = Form.useForm();
  const queryClient = useQueryClient();
  const [editingConfig, setEditingConfig] = useState<LLMConfiguration | null>(
    null,
  );

  const {
    data: llmConfigs,
    isLoading,
    isError,
    error,
  } = useQuery<LLMConfiguration[], Error>({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

  useEffect(() => {
    if (editingConfig) {
      form.setFieldsValue({
        ...editingConfig,
        // Ensure field names match the form items and the LLMConfiguration type
        input_cost_per_million: editingConfig.input_cost_per_million, 
        output_cost_per_million: editingConfig.output_cost_per_million,
        tokenizer_encoding: editingConfig.tokenizer_encoding,
        api_key: "", // Clear API key for editing
      });
    } else {
      form.resetFields();
    }
  }, [editingConfig, form]);

  const handleApiError = (
    err: AxiosError,
    action: "create" | "update" | "delete",
  ) => {
    const errorDetail =
      (err.response?.data as { detail?: string | { msg: string }[] })
        ?.detail || "An unknown error occurred.";
    if (Array.isArray(errorDetail)) {
      const messages = errorDetail.map((d) => d.msg).join(", ");
      message.error(`Failed to ${action} configuration: ${messages}`);
    } else {
      message.error(`Failed to ${action} configuration: ${errorDetail}`);
    }
  };

  const createMutation = useMutation<
    LLMConfiguration,
    AxiosError,
    LLMConfigurationCreate
  >({
    mutationFn: llmConfigService.createLlmConfig,
    onSuccess: () => {
      message.success("LLM configuration created successfully!");
      queryClient.invalidateQueries({ queryKey: ["llmConfigs"] });
      form.resetFields();
    },
    onError: (err) => handleApiError(err, "create"),
  });

  const updateMutation = useMutation<
    LLMConfiguration,
    AxiosError,
    { id: string; data: LLMConfigurationUpdate }
  >({
    mutationFn: ({ id, data }) => llmConfigService.updateLlmConfig(id, data),
    onSuccess: () => {
      message.success("LLM configuration updated successfully!");
      queryClient.invalidateQueries({ queryKey: ["llmConfigs"] });
      setEditingConfig(null);
    },
    onError: (err) => handleApiError(err, "update"),
  });

  const deleteMutation = useMutation<void, AxiosError, string>({
    mutationFn: llmConfigService.deleteLlmConfig,
    onSuccess: () => {
      message.success("LLM configuration deleted successfully!");
      queryClient.invalidateQueries({ queryKey: ["llmConfigs"] });
    },
    onError: (err) => handleApiError(err, "delete"),
  });

  const handleSubmit = (values: LLMConfigurationCreate) => {
    // Ensure field names here match what the backend expects (LLMConfigurationUpdate)
    // and what the form provides.
    const payload = {
      ...values,
      input_cost_per_million: Number(values.input_cost_per_million),
      output_cost_per_million: Number(values.output_cost_per_million),
      // tokenizer_encoding is already a string from the form
    };

    if (editingConfig) {
      if (!payload.api_key) {
        delete (payload as Partial<LLMConfigurationCreate>).api_key;
      }
      updateMutation.mutate({ id: editingConfig.id, data: payload });
    } else {
      createMutation.mutate(payload);
    }
  };

  const handleCancelEdit = () => {
    setEditingConfig(null);
  };

  const parseAsUTCDate = (
    dateString: string | null | undefined,
  ): Date | null => {
    if (!dateString) return null;
    let utcDateString = dateString;
    if (!/Z|[+-]\d{2}:\d{2}$/.test(dateString)) {
      utcDateString += "Z";
    }
    const date = new Date(utcDateString);
    return isNaN(date.getTime()) ? null : date;
  };

  const formatDisplayDate = useCallback(
    (dateString: string | null | undefined): string => {
      const date = parseAsUTCDate(dateString);
      return date ? date.toLocaleString() : "N/A";
    },
    [],
  );

  const handleDelete = useCallback(
    (configId: string) => {
      deleteMutation.mutate(configId);
    },
    [deleteMutation],
  );

  const columns: TableProps<LLMConfiguration>["columns"] = useMemo(
    () => [
      { title: "Name", dataIndex: "name", key: "name", sorter: (a, b) => a.name.localeCompare(b.name) },
      { title: "Provider", dataIndex: "provider", key: "provider", render: (provider) => <Tag>{provider.toUpperCase()}</Tag>, filters: LLM_PROVIDERS.map((p) => ({ text: p.toUpperCase(), value: p })), onFilter: (value, record) => record.provider === value },
      { title: "Model Name", dataIndex: "model_name", key: "model_name" },
      { title: "Input Cost ($/1M)", dataIndex: "input_cost_per_million", key: "input_cost_per_million", render: (cost) => <Text>${cost ? cost.toFixed(6) : "0.00"}</Text>, sorter: (a, b) => a.input_cost_per_million - b.input_cost_per_million },
      { title: "Output Cost ($/1M)", dataIndex: "output_cost_per_million", key: "output_cost_per_million", render: (cost) => <Text>${cost ? cost.toFixed(6) : "0.00"}</Text>, sorter: (a, b) => a.output_cost_per_million - b.output_cost_per_million },
      { title: "Tokenizer", dataIndex: "tokenizer_encoding", key: "tokenizer_encoding", render: (name) => (name ? <Tag color="blue">{name}</Tag> : <Text type="secondary">Default</Text>) },
      { title: "Created At", dataIndex: "created_at", key: "created_at", render: (text) => formatDisplayDate(text), sorter: (a, b) => (parseAsUTCDate(a.created_at)?.getTime() || 0) - (parseAsUTCDate(b.created_at)?.getTime() || 0) },
      { title: "Action", key: "action", render: (_, record) => (
          <Space>
            <Button icon={<EditOutlined />} onClick={() => setEditingConfig(record)} disabled={editingConfig?.id === record.id}>Edit</Button>
            <Popconfirm title="Delete this configuration?" description="This action cannot be undone." onConfirm={() => handleDelete(record.id)} okText="Yes" cancelText="No">
              <Button danger icon={<DeleteOutlined />} loading={deleteMutation.isPending && deleteMutation.variables === record.id}>Delete</Button>
            </Popconfirm>
          </Space>
        ),
      },
    ],
    [formatDisplayDate, handleDelete, deleteMutation, editingConfig],
  );

  if (isError) {
    message.error(`Error fetching configurations: ${error.message}`);
  }

  const isMutating = createMutation.isPending || updateMutation.isPending;
  
  // --- NEW: Custom validator for cost fields ---
  const costValidator = (_: RuleObject, value: string) => {
    if (value && (isNaN(parseFloat(value)) || parseFloat(value) < 0)) {
        return Promise.reject(new Error("Please enter a valid positive number."));
    }
    return Promise.resolve();
  };

  return (
    <Space direction="vertical" size="large" style={{ display: "flex" }}>
      <Card>
        <Title level={3}>{editingConfig ? `Edit: ${editingConfig.name}` : "Create New LLM Configuration"}</Title>
        <Paragraph type="secondary">{editingConfig ? "Update the details for this configuration." : "Add a new Large Language Model provider configuration."}</Paragraph>
        <Form form={form} layout="vertical" onFinish={handleSubmit}>
          <Row gutter={24}><Col xs={24} sm={12}><Form.Item name="name" label="Configuration Name" rules={[{ required: true, message: "Please enter a unique name." }]}><Input placeholder="e.g., OpenAI GPT-4o Mini" /></Form.Item></Col><Col xs={24} sm={12}><Form.Item name="provider" label="Provider" rules={[{ required: true, message: "Please select a provider." }]}><Select placeholder="Select a provider">{LLM_PROVIDERS.map((p) => (<Option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</Option>))}</Select></Form.Item></Col></Row>
          <Row gutter={24}><Col xs={24} sm={12}><Form.Item name="model_name" label="Model Name" rules={[{ required: true, message: "Please enter the model name." }]}><Input placeholder="e.g., gpt-4o-mini" /></Form.Item></Col><Col xs={24} sm={12}><Form.Item name="tokenizer_encoding" label="Tokenizer Encoding (Optional)" tooltip="e.g., 'cl100k_base'. Leave blank for default."><Input placeholder="e.g., cl100k_base" /></Form.Item></Col></Row>
          <Row gutter={24}>
            <Col xs={24} sm={12}>
              {/* --- UPDATED: Using the custom validator --- */}
              <Form.Item name="input_cost_per_million" label="Input Cost per 1,000,000 Tokens ($)" rules={[{ required: true, message: "Input cost is required." }, { validator: costValidator }]}>
                <InputNumber style={{ width: "100%" }} placeholder="e.g., 0.15" step="0.01" stringMode />
              </Form.Item>
            </Col>
            <Col xs={24} sm={12}>
              {/* --- UPDATED: Using the custom validator --- */}
              <Form.Item name="output_cost_per_million" label="Output Cost per 1,000,000 Tokens ($)" rules={[{ required: true, message: "Output cost is required." }, { validator: costValidator }]}>
                <InputNumber style={{ width: "100%" }} placeholder="e.g., 0.60" step="0.01" stringMode />
              </Form.Item>
            </Col>
          </Row>
          <Form.Item name="api_key" label="API Key" rules={[{ required: !editingConfig, message: "API key is required for new configurations." }]}>
            <Input.Password placeholder={editingConfig ? "Leave blank to keep existing key" : "Enter secret API key"} />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit" icon={editingConfig ? <EditOutlined /> : <PlusOutlined />} loading={isMutating}>{editingConfig ? "Update Configuration" : "Create Configuration"}</Button>
              {editingConfig && (<Button icon={<ClearOutlined />} onClick={handleCancelEdit}>Cancel</Button>)}
            </Space>
          </Form.Item>
        </Form>
      </Card>
      <Card>
        <Title level={3}>Existing LLM Configurations</Title>
        <Table columns={columns} dataSource={llmConfigs} loading={isLoading} rowKey="id" pagination={{ pageSize: 10, showSizeChanger: true }} scroll={{ x: true }} />
      </Card>
    </Space>
  );
};

export default LLMSettingsPage;
