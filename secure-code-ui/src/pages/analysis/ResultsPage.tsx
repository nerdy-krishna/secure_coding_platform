// src/pages/ResultsPage.tsx

import {
  ArrowLeftOutlined,
  BugOutlined,
  CodeOutlined,
  DownloadOutlined, // ADDED
  FileTextOutlined,
  InfoCircleOutlined,
  LoadingOutlined,
  ProfileOutlined,
  RocketOutlined, // ADDED
  SafetyCertificateOutlined,
  ToolOutlined,
} from "@ant-design/icons";
import { useMutation, useQueryClient } from "@tanstack/react-query";
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
  Row,
  Space,
  Spin,
  Statistic,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { AxiosError } from "axios";
import React, { useCallback, useEffect, useMemo, useState } from "react"; // useMemo is now used correctly
// prettier-ignore
import ReactDiffViewer, { DiffMethod } from "react-diff-viewer-continued";
import { Link, useNavigate, useParams } from "react-router-dom";
import { submissionService, triggerRemediation } from "../../services/submissionService";
import {
  type AnalysisResultResponse,
  type Finding,
  type OverallRiskScore,
  type SubmittedFile,
  type Summary
} from "../../types/api";
import { SeverityColors, SeverityTags } from "../../utils/severityMappings";

// Import our new components
import RemediationModal from "../../components/RemediationModal";
import apiClient from '../../services/apiClient';

const { Content } = Layout;
const { Title, Text, Paragraph } = Typography;
const { TabPane } = Tabs;
const { Panel } = Collapse;

// Helper to map severity to color for AntD components remains the same
const getSeverityTagColor = (severity?: string): string => {
  if (!severity) return "default";
  const upperSeverity = severity.toUpperCase();
  if (upperSeverity in SeverityColors) {
    return SeverityColors[upperSeverity as keyof typeof SeverityColors];
  }
  return "default";
};

const ResultsPage: React.FC = () => {
  const { submissionId } = useParams<{ submissionId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient(); // ADDED

  const [result, setResult] = useState<AnalysisResultResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeFileKey, setActiveFileKey] = useState<string | undefined>(undefined);
  const [isRemediationModalVisible, setIsRemediationModalVisible] = useState(false); // ADDED

  const allFindings: Finding[] = useMemo(() => 
    result?.summary_report?.files_analyzed?.flatMap(file => file.findings) || [],
    [result]
  );

  // Your existing data fetching logic is preserved
  const fetchAnalysisResults = useCallback(async () => {
    if (!submissionId) {
      setError("Submission ID is missing.");
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      // The service call is the same, but the 'data' will now contain our new fields
      const data = await submissionService.getAnalysisResult(submissionId);
      setResult(data);
      setError(null);
      if (
        data.summary_report?.files_analyzed &&
        data.summary_report.files_analyzed.length > 0
      ) {
        setActiveFileKey(data.summary_report.files_analyzed[0].file_path);
      }
    } catch (err) {
      console.error("Error fetching analysis results:", err);
      let errorMessage = "Failed to fetch analysis results. Please try again later.";
      if (err instanceof AxiosError && err.response) {
        const responseData = err.response.data as { detail?: string; message?: string; error?: string; };
        if (responseData.detail) {
          errorMessage = `Error: ${responseData.detail}`;
        } else if (err.response.status === 404) {
          errorMessage = "Analysis result not found. It might still be processing or the ID is incorrect.";
        }
      } else if (err instanceof Error) {
        errorMessage = err.message;
      }
      setError(errorMessage);
      message.error(errorMessage);
    } finally {
      setLoading(false);
    }
  }, [submissionId]);

  useEffect(() => {
    fetchAnalysisResults();
  }, [fetchAnalysisResults]);

  // ADDED: Mutation for triggering remediation
  const remediationMutation = useMutation({
    mutationFn: ({ categories }: { categories: string[] }) => {
        if (!submissionId) {
            throw new Error("Submission ID is missing");
        }
        return triggerRemediation(submissionId, { categories_to_fix: categories });
    },
    onSuccess: (data) => {
        message.success(data.message || "Remediation successfully queued!");
        setIsRemediationModalVisible(false);
        // Refetch history to show the new "Queued for Remediation" status
        queryClient.invalidateQueries({ queryKey: ["submissionHistory"] });
        // After a short delay, navigate user to the history page
        setTimeout(() => navigate('/account/history'), 2000);
    },
    onError: (err: AxiosError) => {
        const errorDetail = (err.response?.data as { detail?: string })?.detail || err.message;
        message.error(`Remediation failed: ${errorDetail}`);
    }
  });

   // Your helper functions and render logic for file tabs are preserved
  const getFindingColor = (severity?: string): string => {
    if (!severity) return "grey";
    const upperSeverity = severity.toUpperCase();
    return (SeverityColors[upperSeverity as keyof typeof SeverityColors] || "grey");
  };

  // Your existing loading, error, and empty states are preserved
  if (loading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh" }}>
        <Spin indicator={<LoadingOutlined style={{ fontSize: 48 }} spin />} tip="Loading results..." />
      </div>
    );
  }

  if (error) {
    return (
      <Content style={{ padding: "20px", margin: "0 auto", maxWidth: "1000px" }}>
        <Alert message="Error" description={error} type="error" showIcon />
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate(-1)} style={{ marginTop: 20 }}>
          Go Back
        </Button>
      </Content>
    );
  }

  if (!result) {
    return (
      <Content style={{ padding: "20px", margin: "0 auto", maxWidth: "1000px" }}>
        <Empty description="No analysis results found or result is still processing." />
        <Button icon={<ArrowLeftOutlined />} onClick={() => navigate(-1)} style={{ marginTop: 20 }}>
          Go Back
        </Button>
      </Content>
    );
  }

  // Your existing data destructuring is preserved
  const {
    summary_report,
    sarif_report,
    text_report,
    original_code_map,
    fixed_code_map,
    // The impact_report is still available but will be linked to, not displayed directly
  } = result;
  const summary: Summary | undefined = summary_report?.summary;
  const filesAnalyzed: SubmittedFile[] | undefined = summary_report?.files_analyzed;
  const overallRisk: OverallRiskScore | undefined = summary_report?.overall_risk_score;
  
  const handleStartRemediation = () => {
    setIsRemediationModalVisible(true);
  };
  
  const handleRemediationSubmit = (categories: string[]) => {
    remediationMutation.mutate({ categories });
  };
  
  const downloadUrl = `${apiClient.defaults.baseURL}/submissions/${submissionId}/download`;

  const renderFileTabs = () => {
    // ... This entire function remains exactly the same as your existing code ...
    if (!filesAnalyzed || filesAnalyzed.length === 0) {
      return <Empty description="No files were analyzed or file data is unavailable." />;
    }
    // (For brevity, the large renderFileTabs function from your file is omitted here, but it should be kept)
    return (
      <Tabs activeKey={activeFileKey} onChange={setActiveFileKey} type="card">
        {filesAnalyzed.map((file) => (
          <TabPane tab={file.file_path} key={file.file_path}>
            <Title level={4}>Details for {file.file_path}</Title>
            <Descriptions bordered column={1} size="small" style={{ marginBottom: 20 }}>
              <Descriptions.Item label="Language">
                {file.language || "N/A"}
              </Descriptions.Item>
              <Descriptions.Item label="Analysis Summary">
                {file.analysis_summary ? (
                  <Paragraph>{file.analysis_summary}</Paragraph>
                ) : (
                  "N/A"
                )}
              </Descriptions.Item>
              <Descriptions.Item label="Identified Components">
                {file.identified_components &&
                file.identified_components.length > 0
                  ? file.identified_components.map((comp: string) => (
                      <Tag key={comp}>{comp}</Tag>
                    ))
                  : "N/A"}
              </Descriptions.Item>
              <Descriptions.Item label="ASVS Analysis">
                {file.asvs_analysis &&
                Object.keys(file.asvs_analysis).length > 0 ? (
                  <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                    {JSON.stringify(file.asvs_analysis, null, 2)}
                  </pre>
                ) : (
                  "N/A"
                )}
              </Descriptions.Item>
            </Descriptions>

            <Title level={5}>Findings for {file.file_path}</Title>
            {file.findings && file.findings.length > 0 ? (
              <Collapse accordion>
                {file.findings.map((finding, index) => (
                  <Panel
                    header={
                      <Space>
                        <Tooltip
                          title={`Severity: ${finding.severity || "N/A"}`}
                        >
                          <Tag
                            color={getFindingColor(finding.severity)}
                            style={{ minWidth: "60px", textAlign: "center" }}
                          >
                            {SeverityTags[
                              finding.severity?.toUpperCase() as keyof typeof SeverityTags
                            ] ||
                              finding.severity ||
                              "N/A"}
                          </Tag>
                        </Tooltip>
                        {/* Backend provides 'description', frontend uses 'message' in header. Using finding.description here. */}
                        <Text strong>{finding.description || finding.message || "No title"}</Text> 
                        <Text type="secondary">
                          - CWE: {finding.cwe || "N/A"} (Rule:
                          {finding.rule_id || "N/A"})
                        </Text>
                      </Space>
                    }
                    key={`${file.file_path}-finding-${index}`}
                  >
                    <Descriptions bordered column={1} size="small">
                      <Descriptions.Item label="Line">
                        {finding.line_number || "N/A"}
                      </Descriptions.Item>
                      <Descriptions.Item label="Description">
                        <Paragraph>
                          {finding.description || "No description available."}
                        </Paragraph>
                      </Descriptions.Item>
                      <Descriptions.Item label="Remediation">
                        <Paragraph>
                          {finding.remediation || "No remediation advice available."}
                        </Paragraph>
                      </Descriptions.Item>
                      <Descriptions.Item label="Confidence">
                        {finding.confidence || "N/A"}
                      </Descriptions.Item>
                      <Descriptions.Item label="References">
                        {finding.references && finding.references.length > 0 ? (
                          <ul>
                            {finding.references.map((ref: string, i: number) => (
                              <li key={i}>
                                <a
                                  href={ref}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                >
                                  {ref}
                                </a>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          "N/A"
                        )}
                      </Descriptions.Item>
                      <Descriptions.Item label="ASVS Categories (Finding Specific)">
                        {/* This field is not in the current backend VulnerabilityFinding model */}
                        {finding.asvs_categories &&
                        finding.asvs_categories.length > 0
                          ? finding.asvs_categories.join(", ")
                          : "N/A (Not in current backend model)"}
                      </Descriptions.Item>
                      <Descriptions.Item label="Attack Name Summary">
                         {/* This field is not in the current backend VulnerabilityFinding model */}
                        {finding.attack_name_summary || "N/A (Not in current backend model)"}
                      </Descriptions.Item>
                    </Descriptions>
                    
                    {finding.fixes && finding.fixes.length > 0 && (
                      <Card
                        size="small"
                        title="Suggested Fixes"
                        style={{ marginTop: 10 }}
                      >
                        <Collapse>
                          {finding.fixes.map((fix: { description?: string; suggested_fix?: string }, fixIndex: number) => (
                            <Panel
                              header={fix.description || `Suggested Fix ${fixIndex + 1}`}
                              key={`${file.file_path}-finding-${index}-fix-${fixIndex}`}
                            >
                              <Text strong>Description:</Text>
                              <Paragraph>{fix.description || "N/A"}</Paragraph>
                              <Text strong>Suggested Code:</Text>
                              <pre style={{ whiteSpace: "pre-wrap", background: "#f5f5f5", padding: "10px", borderRadius: "4px" }}>
                                {fix.suggested_fix || "No code suggestion."}
                              </pre>
                            </Panel>
                          ))}
                        </Collapse>
                      </Card>
                    )}

                    {finding.code_snippet && (
                      <Card
                        size="small"
                        title="Original Code Snippet"
                        style={{
                          marginTop: 10,
                          marginBottom: 10,
                          fontFamily: "monospace",
                          whiteSpace: "pre-wrap",
                          background: "#f0f0f0",
                        }}
                      >
                        {finding.code_snippet}
                      </Card>
                    )}
                    {fixed_code_map &&
                      original_code_map &&
                      original_code_map[file.file_path] &&
                      fixed_code_map[`${file.file_path}_fixed`] && (
                        <Card
                          size="small"
                          title="Diff View (Original vs. Suggested Fix)"
                          style={{ marginTop: 10 }}
                        >
                          <ReactDiffViewer
                            oldValue={original_code_map[file.file_path] || ""}
                            newValue={
                              fixed_code_map[`${file.file_path}_fixed`] || ""
                            }
                            splitView={true}
                            compareMethod={DiffMethod.LINES}
                            // useDarkTheme={true} // Optional: if you want a dark theme for the diff
                            leftTitle="Original Code"
                            rightTitle="Suggested Fix"
                          />
                        </Card>
                      )}
                  </Panel>
                ))}
              </Collapse>
            ) : (
              <Empty description="No findings for this file." />
            )}
          </TabPane>
        ))}
      </Tabs>
    );
  };


  return (
    <Content style={{ padding: "20px 50px", margin: "0 auto", maxWidth: "1200px" }}>
      <Row justify="space-between" align="middle" style={{ marginBottom: 20 }}>
        <Col>
            <Button icon={<ArrowLeftOutlined />} onClick={() => navigate("/account/history")}>
                Back to Submission History
            </Button>
        </Col>
        <Col>
            <Space>
                {fixed_code_map && Object.keys(fixed_code_map).length > 0 && (
                     <a href={downloadUrl} download>
                        <Button type="default" icon={<DownloadOutlined />}>
                            Download Fixed Code
                        </Button>
                    </a>
                )}
                {result.status === "Completed" && (
                    <Button type="primary" icon={<RocketOutlined />} onClick={handleStartRemediation}>
                        Begin Remediation
                    </Button>
                )}
            </Space>
        </Col>
      </Row>

      <Title level={2}><ProfileOutlined /> Analysis Results</Title>
      <Text type="secondary">Submission ID: {submissionId}</Text>
      
      {/* --- UPDATED: Display the new Impact Report as a link --- */}
      {result.impact_report && (
        <Card size="small" style={{ marginTop: 24, backgroundColor: '#e6f4ff', borderColor: '#91caff' }}>
            <Space>
                <InfoCircleOutlined style={{color: '#1677ff', fontSize: '18px'}}/>
                <Text>An AI-generated executive summary is available for this report.</Text>
                <Link to={`/analysis/results/${submissionId}/executive-summary`}>
                    <Button type="primary" size="small">View Full Executive Summary</Button>
                </Link>
            </Space>
        </Card>
      )}

      {/* Your existing summary card is preserved */}
      {summary && (
        <Card 
          title={
            <>
            <InfoCircleOutlined /> Statistics Summary
            </>
          }
          style={{ marginTop: 20, marginBottom: 20 }}
          headStyle={{ backgroundColor: "#f0f2f5" }}
        >
          <Row gutter={16}>
            <Col span={8}>
              <Statistic
                title="Total Findings"
                value={summary.total_findings_count || 0}
                prefix={<BugOutlined />}
              />
            </Col>
            <Col span={8}>
              <Statistic
                title="Files Analyzed"
                value={summary.files_analyzed_count || 0}
                prefix={<FileTextOutlined />}
              />
            </Col>
            <Col span={8}>
              <Statistic
                title="Risk Score"
                value={overallRisk?.score || "N/A"}
                prefix={<SafetyCertificateOutlined />}
                valueStyle={{
                  color: getSeverityTagColor(overallRisk?.severity),
                }}
              />
              <Text type="secondary">
                Severity: {overallRisk?.severity || "N/A"}
              </Text>
            </Col>
          </Row>
          <Descriptions
            bordered
            column={2}
            size="small"
            style={{ marginTop: 20 }}
          >
            <Descriptions.Item label="Primary Language">
              {summary_report?.primary_language || "N/A"}
            </Descriptions.Item>
            <Descriptions.Item label="Analysis Date">
              {summary_report?.analysis_timestamp
                ? new Date(summary_report.analysis_timestamp).toLocaleString()
                : "N/A"}
            </Descriptions.Item>
            <Descriptions.Item label="Critical Vulnerabilities">
              {summary.severity_counts?.CRITICAL || 0}
            </Descriptions.Item>
            <Descriptions.Item label="High Vulnerabilities">
              {summary.severity_counts?.HIGH || 0}
            </Descriptions.Item>
            <Descriptions.Item label="Medium Vulnerabilities">
              {summary.severity_counts?.MEDIUM || 0}
            </Descriptions.Item>
            <Descriptions.Item label="Low Vulnerabilities">
              {summary.severity_counts?.LOW || 0}
            </Descriptions.Item>
            <Descriptions.Item label="Informational Findings">
              {summary.severity_counts?.INFORMATIONAL || 0}
            </Descriptions.Item>
          </Descriptions>
        </Card>
      )}

      
      <Title level={3} style={{ marginTop: 30 }}><FileTextOutlined /> Detailed Findings by File</Title>
      {renderFileTabs()}

      
      <Tabs defaultActiveKey="text" style={{ marginTop: 30 }}>
        <TabPane
          tab={
            <>
              <ToolOutlined /> Text Report
            </>
          }
          key="text"
        >
          <Card title="Full Text Report">
            <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {text_report || "Text report not available."}
            </pre>
          </Card>
        </TabPane>
        <TabPane tab={<><CodeOutlined /> SARIF Report (JSON)</>} key="sarif">
          <Card title="SARIF Output">
            <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {sarif_report ? JSON.stringify(sarif_report, null, 2) : "SARIF report not available."}
            </pre>
          </Card>
        </TabPane>
      </Tabs>
      {/* ADDED: Render the modal */}
      <RemediationModal
        open={isRemediationModalVisible}
        isLoading={remediationMutation.isPending}
        findings={allFindings}
        onCancel={() => setIsRemediationModalVisible(false)}
        onSubmit={handleRemediationSubmit}
      />
    </Content>
  );
};

export default ResultsPage;