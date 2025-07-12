// src/pages/chat/SecurityAdvisorPage.tsx
import {
  CommentOutlined,
  CopyOutlined,
  DeleteOutlined,
  PlusOutlined,
  RobotOutlined,
  SendOutlined,
  SyncOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Button,
  Card,
  Checkbox,
  Col,
  Empty,
  Form,
  Input,
  Layout,
  List,
  Menu,
  Modal,
  Popconfirm,
  Row,
  Select,
  Skeleton,
  Space,
  Statistic,
  Tag,
  Tooltip,
  Typography,
  message,
} from "antd";
import React, { useEffect, useMemo, useRef, useState } from "react";
import { chatService } from "../../shared/api/chatService";
import { frameworkService } from "../../shared/api/frameworkService";
import { llmConfigService } from "../../shared/api/llmConfigService";
import type {
  ChatMessage,
  ChatSession,
  ChatSessionCreateRequest,
  FrameworkRead,
  LLMConfiguration,
} from "../../shared/types/api";

const { Sider, Content } = Layout;
const { Title, Text, Paragraph } = Typography;
const { Option } = Select;


// --- MODIFIED ChatMessageItem Component ---
const ChatMessageItem: React.FC<{ message: ChatMessage }> = ({ message: chatMessage }) => {
  const isUser = chatMessage.role === "user";

  const handleCopy = () => {
    navigator.clipboard.writeText(chatMessage.content);
    message.success("Copied to clipboard!");
  };

  return (
    <List.Item
      style={{
        display: "flex",
        justifyContent: isUser ? "flex-end" : "flex-start",
        borderBottom: "none",
        padding: "8px 0",
      }}
    >
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: isUser ? 'flex-end' : 'flex-start' }}>
            <Card
                style={{
                maxWidth: "750px", // Increased max-width
                backgroundColor: isUser ? "#e3f2fd" : "#e8f5e9", // New pastel colors
                }}
                size="small"
                bodyStyle={{ padding: '8px 12px' }}
            >
                <Text style={{ whiteSpace: 'pre-wrap' }}>{chatMessage.content}</Text>
            </Card>
            <Space style={{ marginTop: '4px', opacity: 0.7 }}>
                <Text type="secondary" style={{ fontSize: '11px' }}>
                    {new Date(chatMessage.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </Text>
                <Tooltip title="Copy text">
                    <Button
                        type="text"
                        shape="circle"
                        icon={<CopyOutlined />}
                        size="small"
                        onClick={handleCopy}
                    />
                </Tooltip>
            </Space>
        </div>
    </List.Item>
  );
};


const SecurityAdvisorPage: React.FC = () => {
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [selectedLlmId, setSelectedLlmId] = useState<string | undefined>(
    undefined,
  );
  const [isNewChatModalVisible, setIsNewChatModalVisible] = useState(false);
  const [form] = Form.useForm();
  const queryClient = useQueryClient();
  const chatEndRef = useRef<HTMLDivElement>(null);

  const { data: frameworks, isLoading: isLoadingFrameworks } = useQuery<
    FrameworkRead[]
  >({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  const { data: llmConfigs, isLoading: isLoadingLLMs } = useQuery<
    LLMConfiguration[]
  >({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

  const { data: sessions, isLoading: isLoadingSessions } = useQuery<
    ChatSession[]
  >({
    queryKey: ["chatSessions"],
    queryFn: chatService.getSessions,
  });

  const { data: messages, isFetching: isFetchingMessages } = useQuery<
    ChatMessage[]
  >({
    queryKey: ["chatMessages", activeSessionId],
    queryFn: () => {
      if (!activeSessionId) return Promise.resolve([]);
      return chatService.getSessionMessages(activeSessionId);
    },
    enabled: !!activeSessionId,
  });

  const currentSessionDetails = useMemo(() => {
    if (!activeSessionId || !sessions) {
        return { title: "Chat", frameworks: [], cost: 0 };
    }
    const session = sessions.find(s => s.id === activeSessionId);
    const totalCost = messages?.reduce((acc, msg) => acc + (msg.cost || 0), 0) || 0;

    return {
        title: session?.title || "Chat",
        frameworks: session?.frameworks || [],
        cost: totalCost
    }
  }, [activeSessionId, sessions, messages]);


  useEffect(() => {
    if (llmConfigs && llmConfigs.length > 0 && !selectedLlmId) {
      setSelectedLlmId(llmConfigs[0].id);
    }
  }, [llmConfigs, selectedLlmId]);

  const createSessionMutation = useMutation({
    mutationFn: (payload: ChatSessionCreateRequest) => chatService.createSession(payload),
    onSuccess: (newSession) => {
      message.success("New chat session created!");
      queryClient.invalidateQueries({ queryKey: ["chatSessions"] });
      setActiveSessionId(newSession.id);
      setIsNewChatModalVisible(false);
      form.resetFields();
    },
    onError: (error) => {
      message.error(`Failed to create session: ${error.message}`);
    },
  });

  const deleteSessionMutation = useMutation({
    mutationFn: chatService.deleteSession,
    onSuccess: (_, deletedSessionId) => {
      message.success("Chat session deleted.");
      queryClient.invalidateQueries({ queryKey: ["chatSessions"] });
      if (activeSessionId === deletedSessionId) {
        setActiveSessionId(null);
      }
    },
    onError: (error) => {
      message.error(`Failed to delete session: ${error.message}`);
    },
  });

  const askQuestionMutation = useMutation({
    mutationFn: ({
      sessionId,
      question,
    }: {
      sessionId: string;
      question: string;
    }) => chatService.askQuestion(sessionId, question),
    onMutate: async (newMessage) => {
      if (!activeSessionId) return;

      await queryClient.cancelQueries({ queryKey: ["chatMessages", activeSessionId] });
      const previousMessages = queryClient.getQueryData<ChatMessage[]>(["chatMessages", activeSessionId]) || [];
      
      const optimisticMessage: ChatMessage = {
        id: Math.random(),
        role: 'user',
        content: newMessage.question,
        timestamp: new Date().toISOString(),
      };

      queryClient.setQueryData<ChatMessage[]>(
        ["chatMessages", activeSessionId],
        [...previousMessages, optimisticMessage]
      );

      form.resetFields();
      return { previousMessages };
    },
    onError: (err, _newMessage, context) => {
      if (activeSessionId && context?.previousMessages) {
        queryClient.setQueryData(["chatMessages", activeSessionId], context.previousMessages);
      }
      message.error(`Failed to send message: ${err.message}`);
    },
    onSettled: () => {
      if (activeSessionId) {
        queryClient.invalidateQueries({ queryKey: ["chatMessages", activeSessionId] });
      }
    },
  });

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, askQuestionMutation.isPending]);

  const handleCreateSession = (values: { title: string; llm_config_id: string; frameworks: string[] }) => {
    const payload: ChatSessionCreateRequest = {
      title: values.title,
      llm_config_id: values.llm_config_id,
      frameworks: values.frameworks || [],
    };
    createSessionMutation.mutate(payload);
  };

  const handleSendMessage = (values: { question: string }) => {
    if (!activeSessionId || !values.question.trim()) return;
    askQuestionMutation.mutate({
      sessionId: activeSessionId,
      question: values.question,
    });
  };

  return (
    <Layout style={{ height: "calc(100vh - 180px)", background: "#fff" }}>
      <Sider
        width={300}
        style={{ background: "#f5f5f5", padding: "16px", overflowY: "auto" }}
      >
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => setIsNewChatModalVisible(true)}
          style={{ marginBottom: 16, width: "100%" }}
        >
          New Chat
        </Button>
        {isLoadingSessions ? (
          <Skeleton active paragraph={{ rows: 8 }} />
        ) : (
          <Menu
            mode="inline"
            selectedKeys={activeSessionId ? [activeSessionId] : []}
            onClick={({ key }) => setActiveSessionId(key)}
            items={sessions?.map((session: ChatSession) => ({
              key: session.id,
              label: (
                <Row justify="space-between" align="middle" wrap={false}>
                  <Col flex="auto" style={{ overflow: "hidden", textOverflow: "ellipsis" }}>
                    <Tooltip title={session.title}>{session.title}</Tooltip>
                  </Col>
                  <Col flex="none">
                    <Popconfirm
                      title="Delete Chat?"
                      description="This action cannot be undone."
                      onConfirm={(e) => {
                        e?.stopPropagation();
                        deleteSessionMutation.mutate(session.id);
                      }}
                      onCancel={(e) => e?.stopPropagation()}
                      okText="Yes"
                      cancelText="No"
                    >
                      <Button
                        type="text"
                        danger
                        size="small"
                        icon={<DeleteOutlined />}
                        onClick={(e) => e.stopPropagation()}
                      />
                    </Popconfirm>
                  </Col>
                </Row>
              ),
              icon: <CommentOutlined />,
            }))}
          />
        )}
      </Sider>
      <Content
        style={{ padding: "0 24px", display: "flex", flexDirection: "column" }}
      >
        {activeSessionId ? (
          <>
            <Card
              style={{ flexShrink: 0, borderBottom: '1px solid #f0f0f0' }}
              bodyStyle={{padding: '12px 24px'}}
              bordered={false}
            >
                <Row justify="space-between" align="top">
                    <Col>
                        <Title level={4} style={{ margin: 0, display: 'inline-flex', alignItems: 'center' }}>
                            {currentSessionDetails.title}
                            {(isFetchingMessages && !askQuestionMutation.isPending) && (
                                <SyncOutlined spin style={{ marginLeft: 10, color: "#1677ff" }} />
                            )}
                        </Title>
                        <div style={{marginTop: '4px'}}>
                            {currentSessionDetails.frameworks.map(fw => <Tag key={fw} color="blue">{fw}</Tag>)}
                        </div>
                    </Col>
                    <Col style={{textAlign: 'right'}}>
                        <Statistic title="Conversation Cost" value={currentSessionDetails.cost} precision={6} prefix="$" valueStyle={{fontSize: '18px'}}/>
                         <Select
                            value={sessions?.find(s => s.id === activeSessionId)?.llm_config_id}
                            loading={isLoadingLLMs || isLoadingSessions}
                            style={{ width: 200, marginTop: '8px' }}
                            placeholder="Select an LLM"
                            disabled
                            size="small"
                        >
                        {llmConfigs?.map((config) => (
                            <Option key={config.id} value={config.id}>
                            <RobotOutlined style={{ marginRight: 8 }} />
                            {config.name}
                            </Option>
                        ))}
                        </Select>
                    </Col>
                </Row>
            </Card>
            <div
                style={{
                  flexGrow: 1,
                  overflowY: "auto",
                  padding: "0 16px",
                }}
              >
                <List
                  dataSource={messages || []}
                  renderItem={(item) => <ChatMessageItem message={item} />}
                  locale={{
                    emptyText: (
                      <Empty
                        description="Send a message to start the conversation."
                        image={Empty.PRESENTED_IMAGE_SIMPLE}
                        style={{marginTop: '20vh'}}
                      />
                    ),
                  }}
                />
                {askQuestionMutation.isPending && (
                  <List.Item style={{ borderBottom: 'none' }}>
                    <div style={{ display: 'flex', alignItems: 'center' }}>
                        <Skeleton.Avatar active size="default" />
                        <Skeleton.Input active style={{ width: '200px', marginLeft: '12px' }} size="small" />
                    </div>
                  </List.Item>
                )}
                <div ref={chatEndRef} />
              </div>
            <div style={{ padding: '16px', borderTop: '1px solid #f0f0f0' }}>
                <Form
                form={form}
                onFinish={handleSendMessage}
                >
                <Row align="middle">
                    <Col flex="auto">
                    <Form.Item name="question" style={{ marginBottom: 0 }}>
                        <Input.TextArea
                        rows={1}
                        autoSize={{minRows: 1, maxRows: 5}}
                        placeholder="Ask a security question..."
                        onPressEnter={(e) => {
                            if (!e.shiftKey) {
                            e.preventDefault();
                            form.submit();
                            }
                        }}
                        disabled={askQuestionMutation.isPending}
                        />
                    </Form.Item>
                    </Col>
                    <Col flex="none" style={{ marginLeft: 8 }}>
                    <Button
                        type="primary"
                        htmlType="submit"
                        icon={<SendOutlined />}
                        loading={askQuestionMutation.isPending}
                    >
                        Send
                    </Button>
                    </Col>
                </Row>
                </Form>
            </div>
          </>
        ) : (
          <div style={{ textAlign: "center", margin: "auto" }}>
            <Empty
              image={<CommentOutlined style={{ fontSize: '64px', color: '#ccc' }}/>}
              description={
                <>
                  <Title level={3}>Security Advisor</Title>
                  <Paragraph>
                    Select a conversation or start a new one to get expert
                    security advice.
                  </Paragraph>
                </>
              }
            />
          </div>
        )}
      </Content>
      <Modal
        title="Start a New Chat"
        open={isNewChatModalVisible}
        onCancel={() => {
          setIsNewChatModalVisible(false);
          form.resetFields();
        }}
        onOk={() => form.submit()}
        confirmLoading={createSessionMutation.isPending}
        destroyOnClose
      >
        <Form form={form} onFinish={handleCreateSession} layout="vertical">
          <Form.Item
            name="title"
            label="Chat Title"
            rules={[{ required: true, message: "Please enter a title." }]}
          >
            <Input placeholder="e.g., Advice on SQL Injection" />
          </Form.Item>

          <Form.Item
            name="llm_config_id"
            label="Select Language Model"
            rules={[{ required: true, message: "Please select a language model." }]}
          >
            <Select
              loading={isLoadingLLMs}
              placeholder="Choose the LLM for this session"
            >
              {llmConfigs?.map((config) => (
                <Option key={config.id} value={config.id}>
                  <RobotOutlined style={{ marginRight: 8 }} />
                  {config.name}
                </Option>
              ))}
            </Select>
          </Form.Item>
        
          <Form.Item
            name="frameworks"
            label="Security Frameworks (Optional)"
            tooltip="Select frameworks to provide additional context from the knowledge base."
          >
            {isLoadingFrameworks ? (
                <Skeleton active paragraph={{ rows: 2 }} />
            ) : (
                <Checkbox.Group style={{ width: '100%' }}>
                    <Row>
                        {(frameworks || []).map((fw) => (
                            <Col span={12} key={fw.id}>
                                <Checkbox value={fw.name}>{fw.name}</Checkbox>
                            </Col>
                        ))}
                    </Row>
                </Checkbox.Group>
            )}
          </Form.Item>
        </Form>
      </Modal>
    </Layout>
  );
};

export default SecurityAdvisorPage;