// secure-code-ui/src/pages/dashboard/LLMSettingsPage.tsx
import { DeleteOutlined, PlusOutlined } from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
    Button,
    Card,
    Form,
    Input,
    message,
    Popconfirm,
    Select,
    Space,
    Table,
    Tag,
    Typography,
    type TableProps, // <-- FIX 1: Import TableProps for explicit typing
} from "antd";
import React from "react";
import { llmConfigService } from "../../services/llmConfigService";
// FIX 2: Use a type-only import
import { AxiosError } from "axios";
import type { LLMConfiguration, LLMConfigurationCreate } from "../../types/api";

const { Title, Paragraph } = Typography;
const { Option } = Select;

const LLM_PROVIDERS = ["openai", "google", "anthropic"];

const LLMSettingsPage: React.FC = () => {
  const [form] = Form.useForm();
  const queryClient = useQueryClient();

  const {
    data: llmConfigs,
    isLoading,
    isError,
    error,
  } = useQuery<LLMConfiguration[], Error>({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

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
    onError: (err) => {
      const errorDetail =
        (err.response?.data as { detail?: string })?.detail ||
        "An unknown error occurred.";
      message.error(`Failed to create configuration: ${errorDetail}`);
    },
  });

  const deleteMutation = useMutation<void, AxiosError, string>({
    mutationFn: llmConfigService.deleteLlmConfig,
    onSuccess: () => {
      message.success("LLM configuration deleted successfully!");
      queryClient.invalidateQueries({ queryKey: ["llmConfigs"] });
    },
    onError: (err) => {
      const errorDetail =
        (err.response?.data as { detail?: string })?.detail ||
        "An unknown error occurred.";
      message.error(`Failed to delete configuration: ${errorDetail}`);
    },
  });

  const handleCreate = (values: LLMConfigurationCreate) => {
    createMutation.mutate(values);
  };

  const handleDelete = (configId: string) => {
    deleteMutation.mutate(configId);
  };

  // FIX 3: Explicitly type the 'columns' constant
  const columns: TableProps<LLMConfiguration>["columns"] = [
    {
      title: "Name",
      dataIndex: "name",
      key: "name",
      sorter: (a, b) => a.name.localeCompare(b.name),
    },
    {
      title: "Provider",
      dataIndex: "provider",
      key: "provider",
      render: (provider) => <Tag>{provider.toUpperCase()}</Tag>,
      filters: LLM_PROVIDERS.map((p) => ({ text: p.toUpperCase(), value: p })),
      onFilter: (value, record) => record.provider === value,
    },
    {
      title: "Model Name",
      dataIndex: "model_name",
      key: "model_name",
    },
    {
      title: "Created At",
      dataIndex: "created_at",
      key: "created_at",
      render: (text) => new Date(text).toLocaleString(),
      sorter: (a, b) =>
        new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
    },
    {
      title: "Action",
      key: "action",
      render: (_value, record) => (
        <Popconfirm
          title="Delete this configuration?"
          description="This action cannot be undone."
          onConfirm={() => handleDelete(record.id)}
          okText="Yes"
          cancelText="No"
        >
          <Button
            danger
            icon={<DeleteOutlined />}
            loading={
              deleteMutation.isPending && deleteMutation.variables === record.id
            }
          >
            Delete
          </Button>
        </Popconfirm>
      ),
    },
  ];

  if (isError) {
    message.error(`Error fetching configurations: ${error.message}`);
  }

  return (
    <Space direction="vertical" size="large" style={{ display: "flex" }}>
      <Card>
        <Title level={3}>Create New LLM Configuration</Title>
        <Paragraph type="secondary">
          Add a new Large Language Model provider configuration that can be used
          for analysis.
        </Paragraph>
        <Form
          form={form}
          layout="vertical"
          onFinish={handleCreate}
          style={{ maxWidth: 600 }}
        >
          <Form.Item
            name="name"
            label="Configuration Name"
            rules={[
              {
                required: true,
                message: "Please enter a unique name for this configuration.",
              },
            ]}
          >
            <Input placeholder="e.g., OpenAI GPT-4o Mini" />
          </Form.Item>
          <Form.Item
            name="provider"
            label="Provider"
            rules={[{ required: true, message: "Please select a provider." }]}
          >
            <Select placeholder="Select a provider">
              {LLM_PROVIDERS.map((p) => (
                <Option key={p} value={p}>
                  {p.charAt(0).toUpperCase() + p.slice(1)}
                </Option>
              ))}
            </Select>
          </Form.Item>
          <Form.Item
            name="model_name"
            label="Model Name"
            rules={[
              { required: true, message: "Please enter the model name." },
            ]}
          >
            <Input placeholder="e.g., gpt-4o-mini" />
          </Form.Item>
          <Form.Item
            name="api_key"
            label="API Key"
            rules={[{ required: true, message: "Please enter the API key." }]}
          >
            <Input.Password placeholder="Enter secret API key" />
          </Form.Item>
          <Form.Item>
            <Button
              type="primary"
              htmlType="submit"
              icon={<PlusOutlined />}
              loading={createMutation.isPending}
            >
              Create Configuration
            </Button>
          </Form.Item>
        </Form>
      </Card>

      <Card>
        <Title level={3}>Existing LLM Configurations</Title>
        <Table
          columns={columns}
          dataSource={llmConfigs}
          loading={isLoading}
          rowKey="id"
          pagination={{ pageSize: 10 }}
        />
      </Card>
    </Space>
  );
};

export default LLMSettingsPage;