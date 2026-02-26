// src/pages/admin/AgentManagementPage.tsx
import {
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
  RobotOutlined,
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
  Space,
  Table,
  Typography,
  message,
} from "antd";
import { AxiosError } from "axios";
import React, { useEffect, useState } from "react";
import { agentService } from "../../shared/api/agentService";
import type {
  AgentCreate,
  AgentRead,
  AgentUpdate,
} from "../../shared/types/api";

const { Title, Paragraph } = Typography;

const AgentManagementPage: React.FC = () => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingAgent, setEditingAgent] = useState<AgentRead | null>(null);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();

  const {
    data: agents,
    isLoading,
    isError,
    error,
  } = useQuery<AgentRead[], Error>({
    queryKey: ["agents"],
    queryFn: agentService.getAgents,
  });

  useEffect(() => {
    if (editingAgent) {
      form.setFieldsValue(editingAgent);
      setIsModalOpen(true);
    } else {
      form.resetFields();
    }
  }, [editingAgent, form]);

  const handleApiError = (err: unknown, action: string) => {
    const errorDetail =
      err instanceof AxiosError
        ? (err.response?.data as { detail?: string })?.detail
        : "An unknown error occurred.";
    message.error(`Failed to ${action} agent: ${errorDetail}`);
  };

  const createMutation = useMutation({
    mutationFn: agentService.createAgent,
    onSuccess: () => {
      message.success("Agent created successfully!");
      queryClient.invalidateQueries({ queryKey: ["agents"] });
      setIsModalOpen(false);
    },
    onError: (err) => handleApiError(err, "create"),
  });

  const updateMutation = useMutation({
    mutationFn: (data: { agentId: string; agentData: AgentUpdate }) =>
      agentService.updateAgent(data.agentId, data.agentData),
    onSuccess: () => {
      message.success("Agent updated successfully!");
      queryClient.invalidateQueries({ queryKey: ["agents"] });
      setIsModalOpen(false);
    },
    onError: (err) => handleApiError(err, "update"),
  });

  const deleteMutation = useMutation({
    mutationFn: agentService.deleteAgent,
    onSuccess: () => {
      message.success("Agent deleted successfully!");
      queryClient.invalidateQueries({ queryKey: ["agents"] });
    },
    onError: (err) => handleApiError(err, "delete"),
  });

  const handleModalSubmit = async () => {
    try {
      const values = await form.validateFields();
      if (editingAgent) {
        updateMutation.mutate({
          agentId: editingAgent.id,
          agentData: values as AgentUpdate,
        });
      } else {
        createMutation.mutate(values as AgentCreate);
      }
    } catch (info) {
      console.log("Validate Failed:", info);
    }
  };

  const handleCancel = () => {
    setIsModalOpen(false);
    setEditingAgent(null);
  };

  const columns: TableProps<AgentRead>["columns"] = [
    {
      title: "Name",
      dataIndex: "name",
      key: "name",
      sorter: (a, b) => a.name.localeCompare(b.name),
    },
    {
      title: "Description",
      dataIndex: "description",
      key: "description",
      ellipsis: true,
    },
    {
      title: "Domain Query",
      dataIndex: "domain_query",
      key: "domain_query",
      ellipsis: true,
    },
    {
      title: "Action",
      key: "action",
      width: 180,
      render: (_, record) => (
        <Space>
          <Button
            icon={<EditOutlined />}
            onClick={() => setEditingAgent(record)}
          >
            Edit
          </Button>
          <Popconfirm
            title="Delete Agent"
            description="Are you sure you want to delete this agent?"
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

  if (isError) {
    message.error(`Error fetching agents: ${error.message}`);
  }

  return (
    <Card>
      <Title level={2}>
        <RobotOutlined style={{ marginRight: 8 }} /> Agent Management
      </Title>
      <Paragraph type="secondary">
        Create, edit, and manage the specialized AI agents that perform security
        analysis.
      </Paragraph>
      <Button
        type="primary"
        icon={<PlusOutlined />}
        onClick={() => setIsModalOpen(true)}
        style={{ marginBottom: 16 }}
      >
        Create Agent
      </Button>
      <Table
        columns={columns}
        dataSource={agents}
        loading={isLoading}
        rowKey="id"
        scroll={{ x: true }}
      />
      <Modal
        title={editingAgent ? "Edit Agent" : "Create New Agent"}
        open={isModalOpen}
        onOk={handleModalSubmit}
        onCancel={handleCancel}
        confirmLoading={createMutation.isPending || updateMutation.isPending}
        destroyOnClose
        width={720}
      >
        <Form form={form} layout="vertical" name="agent_form">
          <Form.Item
            name="name"
            label="Agent Name"
            rules={[
              { required: true, message: "Please enter the agent name." },
            ]}
          >
            <Input placeholder="e.g., TerraformSecurityAgent" />
          </Form.Item>
          <Form.Item
            name="description"
            label="Description"
            rules={[
              { required: true, message: "Please provide a description." },
            ]}
          >
            <Input.TextArea
              rows={3}
              placeholder="Describe the agent's purpose..."
            />
          </Form.Item>
          <Form.Item
            name="domain_query"
            label="Domain Query for RAG"
            rules={[{ required: true, message: "Please provide a RAG query." }]}
          >
            <Input.TextArea
              rows={4}
              placeholder="Enter comma-separated keywords for fetching context from the knowledge base..."
            />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
};

export default AgentManagementPage;
