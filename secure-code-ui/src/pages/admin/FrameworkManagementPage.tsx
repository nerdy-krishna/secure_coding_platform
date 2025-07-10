// src/pages/admin/FrameworkManagementPage.tsx
import {
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
  SafetyCertificateOutlined,
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
  Tag,
  Typography,
  message,
} from "antd";
import { AxiosError } from "axios";
import React, { useEffect, useState } from "react";
import { agentService } from "../../shared/api/agentService";
import { frameworkService } from "../../shared/api/frameworkService";
import type {
  AgentRead,
  FrameworkCreate,
  FrameworkRead,
  FrameworkUpdate,
} from "../../shared/types/api";

const { Title, Paragraph } = Typography;
const { Option } = Select;

const FrameworkManagementPage: React.FC = () => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingFramework, setEditingFramework] =
    useState<FrameworkRead | null>(null);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();

  const {
    data: frameworks,
    isLoading,
    isError,
    error,
  } = useQuery<FrameworkRead[], Error>({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  const { data: agents = [] } = useQuery<AgentRead[], Error>({
    queryKey: ["agents"],
    queryFn: agentService.getAgents,
  });

  useEffect(() => {
    if (editingFramework) {
      form.setFieldsValue({
        ...editingFramework,
        agent_ids: editingFramework.agents.map((agent) => agent.id),
      });
      setIsModalOpen(true);
    } else {
      form.resetFields();
    }
  }, [editingFramework, form]);

  const handleApiError = (
    err: unknown,
    action: "create" | "update" | "delete",
  ) => {
    const errorDetail =
      err instanceof AxiosError
        ? (err.response?.data as { detail?: string })?.detail
        : "An unknown error occurred.";
    message.error(`Failed to ${action} framework: ${errorDetail}`);
  };

  const createMutation = useMutation({
    mutationFn: frameworkService.createFramework,
    onSuccess: () => {
      message.success("Framework created successfully!");
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
      setIsModalOpen(false);
    },
    onError: (err) => handleApiError(err, "create"),
  });

  const updateMutation = useMutation({
    mutationFn: (data: {
      values: FrameworkUpdate;
      agent_ids: string[];
    }) => {
      if (!editingFramework) throw new Error("No framework selected for update");
      return frameworkService
        .updateFramework(editingFramework.id, data.values)
        .then((updatedFramework) => {
          // Chain the agent mapping update
          return frameworkService.updateAgentMappings(
            updatedFramework.id,
            data.agent_ids,
          );
        });
    },
    onSuccess: () => {
      message.success("Framework updated successfully!");
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
      setIsModalOpen(false);
    },
    onError: (err) => handleApiError(err, "update"),
  });

  const deleteMutation = useMutation({
    mutationFn: frameworkService.deleteFramework,
    onSuccess: () => {
      message.success("Framework deleted successfully!");
      queryClient.invalidateQueries({ queryKey: ["frameworks"] });
    },
    onError: (err) => handleApiError(err, "delete"),
  });

  const handleModalSubmit = async () => {
    try {
      const values = await form.validateFields();
      const agent_ids = values.agent_ids || [];

      if (editingFramework) {
        updateMutation.mutate({ values, agent_ids });
      } else {
        createMutation.mutate(values as FrameworkCreate, {
          onSuccess: (newFramework) => {
            // After creating the framework, update its agent mappings
            if (agent_ids.length > 0) {
              frameworkService.updateAgentMappings(newFramework.id, agent_ids);
            }
          },
        });
      }
    } catch (info) {
      console.log("Validate Failed:", info);
    }
  };

  const handleCancel = () => {
    setIsModalOpen(false);
    setEditingFramework(null);
    form.resetFields();
  };

  const columns: TableProps<FrameworkRead>["columns"] = [
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
    },
    {
      title: "Associated Agents",
      dataIndex: "agents",
      key: "agents",
      render: (agents: FrameworkRead["agents"]) => (
        <Space wrap>
          {agents.length > 0 ? (
            agents.map((agent: AgentRead) => <Tag key={agent.id}>{agent.name}</Tag>)
          ) : (
            <Typography.Text type="secondary">None</Typography.Text>
          )}
        </Space>
      ),
    },
    {
      title: "Action",
      key: "action",
      render: (_, record) => (
        <Space>
          <Button
            icon={<EditOutlined />}
            onClick={() => setEditingFramework(record)}
          >
            Edit
          </Button>
          <Popconfirm
            title="Delete Framework"
            description="Are you sure you want to delete this framework?"
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
    message.error(`Error fetching frameworks: ${error.message}`);
  }

  return (
    <Card>
      <Title level={2}>
        <SafetyCertificateOutlined style={{ marginRight: 8 }} /> Framework
        Management
      </Title>
      <Paragraph type="secondary">
        Create, edit, and manage the security frameworks used for code
        analysis. Associate specialized agents with each framework.
      </Paragraph>
      <Button
        type="primary"
        icon={<PlusOutlined />}
        onClick={() => setIsModalOpen(true)}
        style={{ marginBottom: 16 }}
      >
        Create Framework
      </Button>
      <Table
        columns={columns}
        dataSource={frameworks}
        loading={isLoading}
        rowKey="id"
        scroll={{ x: true }}
      />
      <Modal
        title={editingFramework ? "Edit Framework" : "Create New Framework"}
        open={isModalOpen}
        onOk={handleModalSubmit}
        onCancel={handleCancel}
        confirmLoading={createMutation.isPending || updateMutation.isPending}
        destroyOnClose
      >
        <Form form={form} layout="vertical" name="framework_form">
          <Form.Item
            name="name"
            label="Framework Name"
            rules={[
              { required: true, message: "Please enter the framework name." },
            ]}
          >
            <Input placeholder="e.g., OWASP ASVS v5.0" />
          </Form.Item>
          <Form.Item
            name="description"
            label="Description"
            rules={[
              {
                required: true,
                message: "Please provide a brief description.",
              },
            ]}
          >
            <Input.TextArea rows={4} placeholder="Describe the framework..." />
          </Form.Item>
          <Form.Item name="agent_ids" label="Associated Agents">
            <Select
              mode="multiple"
              allowClear
              style={{ width: "100%" }}
              placeholder="Select agents to associate with this framework"
              loading={!agents}
            >
              {agents.map((agent) => (
                <Option key={agent.id} value={agent.id}>
                  {agent.name}
                </Option>
              ))}
            </Select>
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  );
};

export default FrameworkManagementPage;