// src/pages/admin/PromptManagementPage.tsx
import {
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
  ReadOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { TableProps } from "antd";
import {
  Button,
  Card,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Table,
  Typography,
  message,
} from "antd";
import { AxiosError } from "axios";
import React, { useEffect, useState } from "react";
import { agentService } from "../../shared/api/agentService";
import { promptService } from "../../shared/api/promptService";
import type {
  AgentRead,
  PromptTemplateCreate,
  PromptTemplateRead,
  PromptTemplateUpdate,
} from "../../shared/types/api";

const { Title, Paragraph } = Typography;
const { Option } = Select;

const PROMPT_TEMPLATE_TYPES = ["QUICK_AUDIT", "DETAILED_REMEDIATION", "CHAT"];

const PromptManagementPage: React.FC = () => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingTemplate, setEditingTemplate] =
    useState<PromptTemplateRead | null>(null);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();

  const {
    data: prompts,
    isLoading: isLoadingPrompts,
  } = useQuery<PromptTemplateRead[], Error>({
    queryKey: ["prompts"],
    queryFn: promptService.getPrompts,
  });

  const { data: agents = [] } = useQuery<AgentRead[], Error>({
    queryKey: ["agents"],
    queryFn: agentService.getAgents,
  });

  useEffect(() => {
    if (editingTemplate) {
      form.setFieldsValue(editingTemplate);
      setIsModalOpen(true);
    } else {
      form.resetFields();
    }
  }, [editingTemplate, form]);

  const handleApiError = (
    err: unknown,
    action: "create" | "update" | "delete",
  ) => {
    const errorDetail =
      err instanceof AxiosError
        ? (err.response?.data as { detail?: string })?.detail
        : "An unknown error occurred.";
    message.error(`Failed to ${action} prompt template: ${errorDetail}`);
  };

  const createMutation = useMutation({
    mutationFn: promptService.createPrompt,
    onSuccess: () => {
      message.success("Prompt template created successfully!");
      queryClient.invalidateQueries({ queryKey: ["prompts"] });
      setIsModalOpen(false);
    },
    onError: (err) => handleApiError(err, "create"),
  });

  const updateMutation = useMutation({
    mutationFn: (data: PromptTemplateUpdate) => {
      if (!editingTemplate) throw new Error("No template selected for update");
      return promptService.updatePrompt(editingTemplate.id, data);
    },
    onSuccess: () => {
      message.success("Prompt template updated successfully!");
      queryClient.invalidateQueries({ queryKey: ["prompts"] });
      setIsModalOpen(false);
    },
    onError: (err) => handleApiError(err, "update"),
  });

  const deleteMutation = useMutation({
    mutationFn: promptService.deletePrompt,
    onSuccess: () => {
      message.success("Prompt template deleted successfully!");
      queryClient.invalidateQueries({ queryKey: ["prompts"] });
    },
    onError: (err) => handleApiError(err, "delete"),
  });

  const handleModalSubmit = async () => {
    try {
      const values = await form.validateFields();
      const payload = {
        ...values,
        version: Number(values.version),
      };

      if (editingTemplate) {
        updateMutation.mutate(payload);
      } else {
        createMutation.mutate(payload as PromptTemplateCreate);
      }
    } catch (info) {
      console.log("Validate Failed:", info);
    }
  };

  const handleCancel = () => {
    setIsModalOpen(false);
    setEditingTemplate(null);
    form.resetFields();
  };

  const columns: TableProps<PromptTemplateRead>["columns"] = [
    { title: "Name", dataIndex: "name", key: "name", sorter: (a, b) => a.name.localeCompare(b.name) },
    { title: "Template Type", dataIndex: "template_type", key: "template_type" },
    { title: "Associated Agent", dataIndex: "agent_name", key: "agent_name" },
    { title: "Version", dataIndex: "version", key: "version", sorter: (a, b) => a.version - b.version },
    {
      title: "Action",
      key: "action",
      render: (_, record) => (
        <Space>
          <Button
            icon={<EditOutlined />}
            onClick={() => setEditingTemplate(record)}
          >
            Edit
          </Button>
          <Popconfirm
            title="Delete Prompt Template"
            description="Are you sure you want to delete this template?"
            onConfirm={() => deleteMutation.mutate(record.id)}
            okText="Yes"
            cancelText="No"
          >
            <Button danger icon={<DeleteOutlined />}>
              Delete
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  return (
    <Card>
      <Title level={2}>
        <ReadOutlined style={{ marginRight: 8 }} /> Prompt Template Management
      </Title>
      <Paragraph type="secondary">
        Manage the prompt templates that guide the behavior of specialized AI agents during scans.
      </Paragraph>
      <Button
        type="primary"
        icon={<PlusOutlined />}
        onClick={() => setIsModalOpen(true)}
        style={{ marginBottom: 16 }}
      >
        Create Template
      </Button>
      <Table
        columns={columns}
        dataSource={prompts}
        loading={isLoadingPrompts}
        rowKey="id"
        scroll={{ x: true }}
      />
      <Modal
        title={editingTemplate ? "Edit Prompt Template" : "Create New Prompt Template"}
        open={isModalOpen}
        onOk={handleModalSubmit}
        onCancel={handleCancel}
        confirmLoading={createMutation.isPending || updateMutation.isPending}
        width={800}
        destroyOnClose
      >
        <Form form={form} layout="vertical" name="prompt_template_form" initialValues={{ version: 1 }}>
          <Form.Item
            name="name"
            label="Template Name"
            rules={[{ required: true, message: "Please enter a unique name." }]}
          >
            <Input placeholder="e.g., Python SQLi - Detailed Fix" />
          </Form.Item>
          <Form.Item
            name="template_type"
            label="Template Type"
            rules={[{ required: true, message: "Please select a type." }]}
          >
            <Select placeholder="Select the template type">
              {PROMPT_TEMPLATE_TYPES.map((type) => (
                <Option key={type} value={type}>{type}</Option>
              ))}
            </Select>
          </Form.Item>
           <Form.Item
            name="agent_name"
            label="Associated Agent"
            rules={[{ required: true, message: "Please select an agent." }]}
          >
            <Select placeholder="Select the agent this prompt is for" loading={!agents}>
              {agents.map((agent) => (
                <Option key={agent.id} value={agent.name}>{agent.name}</Option>
              ))}
            </Select>
          </Form.Item>
          <Form.Item
            name="template_text"
            label="Template Content"
            rules={[{ required: true, message: "Template content cannot be empty." }]}
          >
            <Input.TextArea
              rows={15}
              placeholder="Enter the full prompt template text here..."
            />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
};

export default PromptManagementPage;