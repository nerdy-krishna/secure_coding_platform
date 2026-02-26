import React, { useState } from "react";
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
} from "antd";
import { PlusOutlined, EditOutlined, DeleteOutlined } from "@ant-design/icons";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import apiClient from "../../shared/api/apiClient";

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
      render: (text: string) => <Text strong> {text} </Text>,
    },
    {
      title: "Value",
      dataIndex: "value",
      key: "value",
      render: (val: any, record: SystemConfig) => {
        if (record.is_secret) return <Text type="secondary">******** </Text>;
        if (typeof val === "object")
          return <Text code> {JSON.stringify(val)} </Text>;
        return <Text>{String(val)} </Text>;
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
        <div style={{ display: "flex", gap: 8 }}>
          <Button
            icon={<EditOutlined />}
            size="small"
            onClick={() => handleEdit(record)}
          />
          <Popconfirm
            title="Delete setting"
            description="Are you sure you want to delete this setting?"
            onConfirm={() => handleDelete(record.key)}
            okText="Yes"
            cancelText="No"
          >
            <Button
              icon={<DeleteOutlined />}
              size="small"
              danger
              loading={deleteMutation.isPending}
            />
          </Popconfirm>
        </div>
      ),
    },
  ];

  return (
    <div>
      <Title level={2}> System Settings </Title>
      <Paragraph>
        {" "}
        Configure core system behavior, global variables, and environmental
        settings.
      </Paragraph>
      <div
        style={{
          marginBottom: 16,
          display: "flex",
          justifyContent: "flex-end",
        }}
      >
        <Button type="primary" icon={<PlusOutlined />} onClick={handleAdd}>
          Add Setting
        </Button>
      </div>
      <Table
        columns={columns}
        dataSource={configs}
        rowKey="key"
        loading={isLoading}
        pagination={{ pageSize: 10 }}
      />

      <Modal
        title={editingKey ? "Edit Setting" : "Add Setting"}
        open={isModalOpen}
        onOk={handleOk}
        onCancel={() => setIsModalOpen(false)}
        confirmLoading={createMutation.isPending}
      >
        <Form form={form} layout="vertical">
          <Form.Item name="key" label="Key" rules={[{ required: true }]}>
            <Input
              disabled={!!editingKey}
              placeholder="e.g. GLOBAL_ALERT_MESSAGE"
            />
          </Form.Item>
          <Form.Item
            name="value"
            label="Value (JSON)"
            rules={[{ required: true }]}
          >
            <Input.TextArea
              rows={4}
              placeholder='{"message": "Maintenance Mode"}'
            />
          </Form.Item>
          <Form.Item name="description" label="Description">
            <Input placeholder="Short description of this setting" />
          </Form.Item>
          <Form.Item
            name="is_secret"
            label="Is Secret?"
            valuePropName="checked"
          >
            <Switch />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default SystemConfigTab;
