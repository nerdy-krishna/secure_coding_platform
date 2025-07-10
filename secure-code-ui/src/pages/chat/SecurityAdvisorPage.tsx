// src/pages/chat/SecurityAdvisorPage.tsx
import {
    CommentOutlined,
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
    Tooltip,
    Typography,
    message,
} from "antd";
import React, { useEffect, useRef, useState } from "react";
import { chatService } from "../../shared/api/chatService";
import { llmConfigService } from "../../shared/api/llmConfigService";
import type {
    ChatMessage,
    ChatSession,
    LLMConfiguration,
} from "../../shared/types/api";

const { Sider, Content } = Layout;
const { Title, Text, Paragraph } = Typography;
const { Option } = Select;

const ChatMessageItem: React.FC<{ message: ChatMessage }> = ({ message }) => {
  const isUser = message.role === "user";
  return (
    <List.Item
      style={{
        display: "flex",
        justifyContent: isUser ? "flex-end" : "flex-start",
        borderBottom: "none",
        padding: "8px 0",
      }}
    >
      <Card
        style={{
          maxWidth: "75%",
          backgroundColor: isUser ? "#e6f7ff" : "#f0f0f0",
        }}
        size="small"
      >
        <Text>{message.content}</Text>
      </Card>
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

  useEffect(() => {
    // Set default LLM when configs load
    if (llmConfigs && llmConfigs.length > 0 && !selectedLlmId) {
      setSelectedLlmId(llmConfigs[0].id);
    }
  }, [llmConfigs, selectedLlmId]);

  const createSessionMutation = useMutation({
    mutationFn: chatService.createSession,
    onSuccess: (newSession) => {
      message.success("New chat session created!");
      queryClient.invalidateQueries({ queryKey: ["chatSessions"] });
      setActiveSessionId(newSession.id);
      setIsNewChatModalVisible(false);
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
      llmConfigId,
    }: {
      sessionId: string;
      question: string;
      llmConfigId?: string;
    }) => chatService.askQuestion(sessionId, question, llmConfigId),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["chatMessages", activeSessionId],
      });
      form.resetFields();
    },
    onError: (error) => {
      message.error(`Failed to send message: ${error.message}`);
    },
  });

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleCreateSession = (values: { title: string }) => {
    createSessionMutation.mutate({ title: values.title });
  };

  const handleSendMessage = (values: { question: string }) => {
    if (!activeSessionId || !values.question.trim()) return;
    askQuestionMutation.mutate({
      sessionId: activeSessionId,
      question: values.question,
      llmConfigId: selectedLlmId,
    });
  };

  const activeSessionTitle = sessions?.find(
    (s) => s.id === activeSessionId,
  )?.title;

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
            items={sessions?.map((session) => ({
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
              title={
                <Title level={4} style={{ margin: 0 }}>
                  {activeSessionTitle || "Chat"}
                  {isFetchingMessages && (
                    <SyncOutlined
                      spin
                      style={{ marginLeft: 10, color: "#1677ff" }}
                    />
                  )}
                </Title>
              }
              style={{ flexShrink: 0 }}
              extra={
                <Select
                  value={selectedLlmId}
                  onChange={setSelectedLlmId}
                  loading={isLoadingLLMs}
                  style={{ width: 250 }}
                  placeholder="Select an LLM"
                >
                  {llmConfigs?.map((config) => (
                    <Option key={config.id} value={config.id}>
                      <RobotOutlined style={{ marginRight: 8 }} />
                      {config.name}
                    </Option>
                  ))}
                </Select>
              }
            >
              <div
                style={{
                  height: "calc(100vh - 455px)",
                  overflowY: "auto",
                  padding: "0 16px",
                }}
              >
                <List
                  dataSource={messages || []}
                  renderItem={(item) => <ChatMessageItem message={item} />}
                  locale={{
                    emptyText: (
                      <Text type="secondary">
                        Send a message to start the conversation.
                      </Text>
                    ),
                  }}
                />
                <div ref={chatEndRef} />
              </div>
            </Card>
            <Form
              form={form}
              onFinish={handleSendMessage}
              style={{ marginTop: "auto", paddingTop: '16px', flexShrink: 0 }}
            >
              <Row align="middle">
                <Col flex="auto">
                  <Form.Item name="question" style={{ marginBottom: 0 }}>
                    <Input.TextArea
                      rows={2}
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
        onCancel={() => setIsNewChatModalVisible(false)}
        onOk={() => form.submit()}
        confirmLoading={createSessionMutation.isPending}
      >
        <Form form={form} onFinish={handleCreateSession} layout="vertical">
          <Form.Item
            name="title"
            label="Chat Title"
            rules={[{ required: true, message: "Please enter a title." }]}
          >
            <Input placeholder="e.g., Advice on SQL Injection" />
          </Form.Item>
        </Form>
      </Modal>
    </Layout>
  );
};

export default SecurityAdvisorPage;