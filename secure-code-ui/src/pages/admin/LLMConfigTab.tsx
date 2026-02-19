import React, { useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, InputNumber, message, Popconfirm, Tag } from 'antd';
import { PlusOutlined, EditOutlined, DeleteOutlined } from '@ant-design/icons';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import apiClient from '../../shared/api/apiClient';

interface LLMConfig {
    id: string;
    name: string;
    provider: string;
    model_name: string;
    tokenizer?: string;
    input_cost_per_million: number;
    output_cost_per_million: number;
    created_at: string;
}

const LLMConfigTab: React.FC = () => {
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [editingId, setEditingId] = useState<string | null>(null);
    const [form] = Form.useForm();
    const queryClient = useQueryClient();

    const { data: configs, isLoading } = useQuery({
        queryKey: ['llm-configs'],
        queryFn: async () => {
            const res = await apiClient.get<LLMConfig[]>('/admin/llm-config/');
            return res.data;
        },
    });

    const createMutation = useMutation({
        mutationFn: (values: any) => apiClient.post('/admin/llm-config/', values),
        onSuccess: () => {
            message.success('Configuration created successfully');
            setIsModalOpen(false);
            form.resetFields();
            queryClient.invalidateQueries({ queryKey: ['llm-configs'] });
        },
        onError: () => message.error('Failed to create configuration'),
    });

    const updateMutation = useMutation({
        mutationFn: ({ id, values }: { id: string; values: any }) =>
            apiClient.put(`/admin/llm-config/${id}`, values),
        onSuccess: () => {
            message.success('Configuration updated successfully');
            setIsModalOpen(false);
            setEditingId(null);
            form.resetFields();
            queryClient.invalidateQueries({ queryKey: ['llm-configs'] });
        },
        onError: () => message.error('Failed to update configuration'),
    });

    const deleteMutation = useMutation({
        mutationFn: (id: string) => apiClient.delete(`/admin/llm-config/${id}`),
        onSuccess: () => {
            message.success('Configuration deleted successfully');
            queryClient.invalidateQueries({ queryKey: ['llm-configs'] });
        },
        onError: () => message.error('Failed to delete configuration'),
    });

    const handleAdd = () => {
        setEditingId(null);
        form.resetFields();
        setIsModalOpen(true);
    };

    const handleEdit = (record: LLMConfig) => {
        setEditingId(record.id);
        form.setFieldsValue({
            ...record,
            api_key: '', // Do not populate API key
        });
        setIsModalOpen(true);
    };

    const handleDelete = (id: string) => {
        deleteMutation.mutate(id);
    };

    const handleOk = () => {
        form.validateFields().then((values) => {
            if (editingId) {
                // If api_key is empty string, remove it from payload so we don't overwrite with empty
                if (!values.api_key) {
                    delete values.api_key;
                }
                updateMutation.mutate({ id: editingId, values });
            } else {
                createMutation.mutate(values);
            }
        });
    };

    const columns = [
        {
            title: 'Name',
            dataIndex: 'name',
            key: 'name',
            render: (text: string) => <b>{ text } </b>,
        },
        {
            title: 'Provider',
            dataIndex: 'provider',
            key: 'provider',
            render: (provider: string) => {
                let color = 'geekblue';
                if (provider === 'openai') color = 'green';
                if (provider === 'anthropic') color = 'purple';
                if (provider === 'google') color = 'orange';
                return <Tag color={ color }> { provider.toUpperCase() } </Tag>;
            },
        },
        {
            title: 'Model',
            dataIndex: 'model_name',
            key: 'model_name',
        },
        {
            title: 'Input Cost ($/M)',
            dataIndex: 'input_cost_per_million',
            key: 'input_cost_per_million',
            render: (val: number) => `$${val.toFixed(2)}`,
        },
        {
            title: 'Output Cost ($/M)',
            dataIndex: 'output_cost_per_million',
            key: 'output_cost_per_million',
            render: (val: number) => `$${val.toFixed(2)}`,
        },
        {
            title: 'Actions',
            key: 'actions',
            render: (_: any, record: LLMConfig) => (
                <div style= {{ display: 'flex', gap: 8 }}>
                    <Button icon={
    <EditOutlined />} size="small" onClick={() => handleEdit(record)} / >
        <Popconfirm
                        title="Delete configuration"
    description = "Are you sure you want to delete this configuration?"
    onConfirm = {() => handleDelete(record.id)
}
okText = "Yes"
cancelText = "No"
    >
    <Button icon={
    <DeleteOutlined />} size="small" danger loading={deleteMutation.isPending} / >
        </Popconfirm>
        </div>
            ),
},
    ];

return (
    <div>
    <div style= {{ marginBottom: 16, display: 'flex', justifyContent: 'flex-end' }}>
        <Button type="primary" icon = {< PlusOutlined />} onClick = { handleAdd } >
            Add Configuration
                </Button>
                </div>
                < Table
columns = { columns }
dataSource = { configs }
rowKey = "id"
loading = { isLoading }
pagination = {{ pageSize: 10 }}
            />

    < Modal
title = { editingId? 'Edit Configuration': 'Add Configuration' }
open = { isModalOpen }
onOk = { handleOk }
onCancel = {() => setIsModalOpen(false)}
confirmLoading = { createMutation.isPending || updateMutation.isPending }
    >
    <Form form={ form } layout = "vertical" >
        <Form.Item name="name" label = "Name" rules = { [{ required: true }]} >
            <Input placeholder="e.g. GPT-4 Production" />
                </Form.Item>
                < Form.Item name = "provider" label = "Provider" rules = { [{ required: true }]} >
                    <Select>
                    <Select.Option value="openai" > OpenAI </Select.Option>
                        < Select.Option value = "anthropic" > Anthropic </Select.Option>
                            < Select.Option value = "google" > Google(Gemini) </Select.Option>
                                < Select.Option value = "azure" > Azure OpenAI </Select.Option>
                                    < Select.Option value = "ollama" > Ollama(Local) </Select.Option>
                                        </Select>
                                        </Form.Item>
                                        < Form.Item name = "model_name" label = "Model Name" rules = { [{ required: true }]} >
                                            <Input placeholder="e.g. gpt-4-turbo" />
                                                </Form.Item>
                                                < Form.Item
name = "api_key"
label = "API Key"
rules = { [{ required: !editingId, message: 'API Key is required' }]}
help = { editingId? "Leave blank to keep existing key": null }
    >
    <Input.Password placeholder="sk-..." />
        </Form.Item>
        < div style = {{ display: 'flex', gap: 16 }}>
            <Form.Item name="input_cost_per_million" label = "Input Cost ($/1M)" style = {{ flex: 1 }}>
                <InputNumber style={ { width: '100%' } } min = { 0} step = { 0.01} />
                    </Form.Item>
                    < Form.Item name = "output_cost_per_million" label = "Output Cost ($/1M)" style = {{ flex: 1 }}>
                        <InputNumber style={ { width: '100%' } } min = { 0} step = { 0.01} />
                            </Form.Item>
                            </div>
                            < Form.Item name = "tokenizer" label = "Tokenizer (Optional)" >
                                <Input placeholder="e.g. cl100k_base" />
                                    </Form.Item>
                                    </Form>
                                    </Modal>
                                    </div>
    );
};

export default LLMConfigTab;
