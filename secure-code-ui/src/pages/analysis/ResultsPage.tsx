// frontend/src/pages/analysis/ResultsPage.tsx
import {
  ArrowLeftOutlined,
  ExclamationCircleOutlined,
  FileExclamationOutlined,
  LoadingOutlined,
  RocketOutlined,
  SafetyCertificateOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Card,
  Col,
  Collapse,
  Descriptions,
  Empty,
  Layout,
  message,
  Modal,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Tag,
  Typography
} from "antd";
import { AxiosError } from "axios";
import React, { useEffect, useMemo, useState } from "react";
import ReactDiffViewer from "react-diff-viewer-continued";
import { useNavigate, useParams } from "react-router-dom";
import RemediationModal from "../../features/results-display/components/RemediationModal";
import ResultsFileTree from "../../features/results-display/components/ResultsFileTree";
import {
  submissionService,
  triggerRemediation,
} from "../../shared/api/submissionService";
import { SeverityColors } from "../../shared/lib/severityMappings";
import {
  type AnalysisResultResponse
} from "../../shared/types/api";

const { Content, Sider } = Layout;
const { Title, Text, Paragraph } = Typography;
const { Panel } = Collapse;

type SortOption = "severity" | "line" | "cwe";

const SEVERITY_ORDER: { [key: string]: number } = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFORMATIONAL: 1,
  NONE: 0,
};

const ResultsPage: React.FC = () => {
  const { submissionId } = useParams<{ submissionId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [isRemediationModalVisible, setIsRemediationModalVisible] =
    useState(false);
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
  const [sortOrder, setSortOrder] = useState<SortOption>("severity");

  const {
    data: result,
    isLoading,
    isError,
    error,
  } = useQuery<AnalysisResultResponse, Error>({
    queryKey: ["analysisResult", submissionId],
    queryFn: () => {
      if (!submissionId) throw new Error("Submission ID is missing");
      return submissionService.getAnalysisResult(submissionId);
    },
    enabled: !!submissionId,
  });

  const allFindings = useMemo(
    () =>
      result?.summary_report?.files_analyzed?.flatMap((file) => file.findings) ||
      [],
    [result],
  );

  const findingsForSelectedFile = useMemo(() => {
    const findings =
      result?.summary_report?.files_analyzed?.find(
        (file) => file.file_path === selectedFilePath,
      )?.findings || [];

    return [...findings].sort((a, b) => {
      switch (sortOrder) {
        case "line":
          return (a.line_number || 0) - (b.line_number || 0);
        case "cwe":
          return (a.cwe || "").localeCompare(b.cwe || "");
        case "severity":
        default:
          return (
            (SEVERITY_ORDER[b.severity?.toUpperCase() || "NONE"] || 0) -
            (SEVERITY_ORDER[a.severity?.toUpperCase() || "NONE"] || 0)
          );
      }
    });
  }, [result, selectedFilePath, sortOrder]);

  const remediationMutation = useMutation({
    mutationFn: ({ categories }: { categories: string[] }) => {
      if (!submissionId) throw new Error("Submission ID is missing");
      return triggerRemediation(submissionId, {
        categories_to_fix: categories,
      });
    },
    onSuccess: (data) => {
      message.success(data.message || "Remediation successfully queued!");
      setIsRemediationModalVisible(false);
      queryClient.invalidateQueries({ queryKey: ["submissionHistory"] });
      setTimeout(() => navigate("/account/history"), 2000);
    },
    onError: (err: AxiosError) => {
      const errorDetail =
        (err.response?.data as { detail?: string })?.detail || err.message;
      message.error(`Remediation failed: ${errorDetail}`);
    },
  });

  useEffect(() => {
    if (result && !selectedFilePath) {
      const firstFileWithFindings = result.summary_report?.files_analyzed?.find(
        (f) => f.findings.length > 0,
      );
      setSelectedFilePath(
        firstFileWithFindings
          ? firstFileWithFindings.file_path
          : result.summary_report?.files_analyzed?.[0]?.file_path || null,
      );
    }
  }, [result, selectedFilePath]);

  const handleStartRemediation = () => {
    if (result?.status === "Remediation-Completed") {
      Modal.confirm({
        title: "Remediate Again?",
        icon: <ExclamationCircleOutlined />,
        content:
          "This submission has already been remediated. Are you sure you want to start a new remediation run?",
        onOk: () => setIsRemediationModalVisible(true),
      });
    } else {
      setIsRemediationModalVisible(true);
    }
  };

  if (isLoading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh" }} >
        <Spin indicator={<LoadingOutlined style={{ fontSize: 48 }} spin />} tip="Loading results..." />
      </div>
    );
  }

  if (isError) {
    return (
      <Content style={{ padding: "20px" }}>
        <Alert message="Error" description={error.message} type="error" showIcon />
      </Content>
    );
  }

  if (!result) {
    return (
      <Content style={{ padding: "20px", textAlign: "center" }}>
        <Empty description="No analysis results found." />
        <Button onClick={() => navigate(-1)} style={{ marginTop: 24 }}>
            <ArrowLeftOutlined /> Back to History
        </Button>
      </Content>
    );
  }

  const { status, summary_report } = result;

  return (
    <Layout style={{ background: "#fff", height: "calc(100vh - 112px)" }}>
      <Sider width={350} style={{ background: "#f0f2f5", borderRight: "1px solid #d9d9d9", padding: "16px", overflow: "auto" }} >
        <Title level={4} style={{ marginTop: 0, marginBottom: 16 }}>Analyzed Files</Title>
        <ResultsFileTree
          analyzedFiles={summary_report?.files_analyzed || []}
          findings={allFindings}
          onSelect={(keys) => setSelectedFilePath(keys[0] as string)}
        />
      </Sider>
      <Layout style={{ padding: "0 24px 24px" }}>
        <Content>
          <Row justify="space-between" align="middle" style={{ marginTop: 16, marginBottom: 16, flexWrap: 'nowrap' }}>
            <Col flex="auto" style={{minWidth: 0}}>
              <Title level={4} style={{ margin: 0 }} ellipsis={{tooltip: summary_report?.project_name}}>
                Project: {summary_report?.project_name || "N/A"}
              </Title>
              <Text copyable type="secondary">
                ID: {submissionId}
              </Text>
            </Col>
            <Col flex="none">
              {status === "Completed" && (
                <Button type="primary" icon={<RocketOutlined />} onClick={handleStartRemediation}>
                  Begin Remediation
                </Button>
              )}
            </Col>
          </Row>

          <Card size="small" style={{ marginBottom: 24 }}>
            <Row gutter={16}>
              <Col span={6}><Statistic title="Total Findings" value={summary_report?.summary.total_findings_count || 0} prefix={<FileExclamationOutlined />} /></Col>
              <Col span={6}><Statistic title="Critical" value={summary_report?.summary.severity_counts?.CRITICAL || 0} valueStyle={{ color: SeverityColors.CRITICAL }} /></Col>
              <Col span={6}><Statistic title="High" value={summary_report?.summary.severity_counts?.HIGH || 0} valueStyle={{ color: SeverityColors.HIGH }}/></Col>
              <Col span={6}><Statistic title="Risk Score" value={summary_report?.overall_risk_score?.score || 0} prefix={<SafetyCertificateOutlined />} /></Col>
            </Row>
          </Card>

          <Row justify="space-between" align="middle" style={{ marginBottom: 16 }}>
            <Col><Title level={5} style={{ margin: 0 }}>{findingsForSelectedFile.length} findings in {selectedFilePath || 'file'}</Title></Col>
            <Col>
              <Space>
                <Text>Sort by:</Text>
                <Select value={sortOrder} onChange={setSortOrder} style={{width: 120}}>
                  <Select.Option value="severity">Severity</Select.Option>
                  <Select.Option value="line">Line No.</Select.Option>
                  <Select.Option value="cwe">CWE</Select.Option>
                </Select>
              </Space>
            </Col>
          </Row>

          <div style={{maxHeight: 'calc(100vh - 400px)', overflowY: 'auto', paddingRight: '8px'}}>
            {findingsForSelectedFile.length > 0 ? (
              <Collapse accordion>
                {findingsForSelectedFile.map((finding) => (
                  <Panel
                    key={finding.id} // MODIFIED: Use the unique database ID as the key
                    header={
                      <Space>
                        <Tag color={SeverityColors[finding.severity?.toUpperCase() || "DEFAULT"]}>
                          {finding.severity}
                        </Tag>
                        <Text strong>{finding.title}</Text>
                        <Text type="secondary">(CWE-{finding.cwe?.split('-')[1]})</Text>
                      </Space>
                    }
                  >
                    <Descriptions bordered column={1} size="small">
                      <Descriptions.Item label="Details"><Paragraph style={{margin: 0}}>{finding.description}</Paragraph></Descriptions.Item>
                      <Descriptions.Item label="Remediation"><Paragraph style={{margin: 0}}>{finding.remediation}</Paragraph></Descriptions.Item>
                    </Descriptions>
                    {finding.fixes && finding.fixes.length > 0 && finding.fixes[0].original_snippet && (
                       <Card size="small" title="Code Diff" style={{marginTop: 12}}>
                          <ReactDiffViewer
                            oldValue={finding.fixes[0].original_snippet}
                            newValue={finding.fixes[0].suggested_fix}
                            splitView={false}
                            hideLineNumbers={true}
                            showDiffOnly={true}
                            useDarkTheme={true}
                          />
                       </Card>
                    )}
                  </Panel>
                ))}
              </Collapse>
            ) : (
              <Empty description="No findings for this file." style={{marginTop: 48}}/>
            )}
          </div>
        </Content>
      </Layout>
      <RemediationModal open={isRemediationModalVisible} isLoading={remediationMutation.isPending} findings={allFindings} onCancel={() => setIsRemediationModalVisible(false)} onSubmit={(cats) => remediationMutation.mutate({ categories: cats })} />
    </Layout>
  );
};

export default ResultsPage;