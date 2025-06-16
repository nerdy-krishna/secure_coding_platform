import {
  // ... your Ant Design icons ...
  ArrowLeftOutlined, // Example icon
  BugOutlined, // Example icon
  CodeOutlined, // Example icon
  FileTextOutlined,
  InfoCircleOutlined,
  LoadingOutlined,
  ProfileOutlined, // Example icon
  SafetyCertificateOutlined, // Example icon
  ToolOutlined, // Example icon
} from "@ant-design/icons";
import {
  Alert,
  Button,
  Card,
  Col, // Import Tabs
  Collapse,
  Descriptions,
  Empty,
  Layout,
  message, // Import Typography
  Row, // Import Collapse
  Space, // Import Layout
  Spin,
  Statistic,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from "antd";
import { AxiosError } from "axios";
import React, { useCallback, useEffect, useState } from "react";
import ReactDiffViewer, { DiffMethod } from "react-diff-viewer-continued";
import { useNavigate, useParams } from "react-router-dom";
import { submissionService } from "../services/submissionService";
import {
  type AnalysisResultResponse,
  type OverallRiskScore,
  type SubmittedFile,
  type Summary,
} from "../types/api";
import { SeverityColors, SeverityTags } from "../utils/severityMappings";

// Correct Destructuring:
const { Content } = Layout;
const { Title, Text, Paragraph } = Typography;
const { TabPane } = Tabs;
const { Panel } = Collapse;

// Helper to map severity to color for AntD components
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
  const [result, setResult] = useState<AnalysisResultResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeFileKey, setActiveFileKey] = useState<string | undefined>(
    undefined,
  );

  const fetchAnalysisResults = useCallback(async () => {
    if (!submissionId) {
      setError("Submission ID is missing.");
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
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
      // Changed: err: any to err
      console.error("Error fetching analysis results:", err);
      let errorMessage =
        "Failed to fetch analysis results. Please try again later.";
      if (err instanceof AxiosError && err.response) {
        // Assuming error.response.data might have a 'detail' field or some specific structure
        const responseData = err.response.data as {
          detail?: string;
          message?: string;
          error?: string;
        };
        if (responseData.detail) {
          errorMessage = `Error: ${responseData.detail}`;
        } else if (responseData.message) {
          errorMessage = `Error: ${responseData.message}`;
        } else if (responseData.error) {
          errorMessage = `Error: ${responseData.error}`;
        } else if (err.response.status === 404) {
          errorMessage =
            "Analysis result not found. It might still be processing or the ID is incorrect.";
        } else if (err.response.status === 401) {
          errorMessage = "Unauthorized. Please log in again.";
          navigate("/login"); // Redirect to login
        }
      } else if (err instanceof Error) {
        errorMessage = err.message;
      }
      setError(errorMessage);
      message.error(errorMessage);
    } finally {
      setLoading(false);
    }
  }, [submissionId, navigate]);

  useEffect(() => {
    fetchAnalysisResults();
  }, [fetchAnalysisResults]);

  if (loading) {
    return (
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          height: "100vh",
        }}
      >
        <Spin
          indicator={<LoadingOutlined style={{ fontSize: 48 }} spin />}
          tip="Loading results..."
        />
      </div>
    );
  }

  if (error) {
    return (
      <Content
        style={{ padding: "20px", margin: "0 auto", maxWidth: "1000px" }}
      >
        <Alert message="Error" description={error} type="error" showIcon />
        <Button
          icon={<ArrowLeftOutlined />}
          onClick={() => navigate(-1)}
          style={{ marginTop: 20 }}
        >
          Go Back
        </Button>
      </Content>
    );
  }

  if (!result) {
    return (
      <Content
        style={{ padding: "20px", margin: "0 auto", maxWidth: "1000px" }}
      >
        <Empty description="No analysis results found or result is still processing." />
        <Button
          icon={<ArrowLeftOutlined />}
          onClick={() => navigate(-1)}
          style={{ marginTop: 20 }}
        >
          Go Back
        </Button>
      </Content>
    );
  }

  const {
    summary_report,
    sarif_report,
    text_report,
    original_code_map,
    fixed_code_map,
  } = result;
  const summary: Summary | undefined = summary_report?.summary;
  const filesAnalyzed: SubmittedFile[] | undefined =
    summary_report?.files_analyzed;
  const overallRisk: OverallRiskScore | undefined =
    summary_report?.overall_risk_score;

  // const allFindings: Finding[] =
  //   filesAnalyzed?.flatMap((file) => file.findings || []) || [];

  const getFindingColor = (severity?: string): string => {
    // Changed: severity: any to severity?: string
    if (!severity) return "grey"; // Default color if severity is undefined
    const upperSeverity = severity.toUpperCase();
    return (
      SeverityColors[upperSeverity as keyof typeof SeverityColors] || "grey"
    );
  };

  const renderFileTabs = () => {
    if (!filesAnalyzed || filesAnalyzed.length === 0) {
      return (
        <Empty description="No files were analyzed or file data is unavailable." />
      );
    }

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
                  ? file.identified_components.map((comp) => (
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
                            {finding.references.map((ref, i) => (
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
                          {finding.fixes.map((fix, fixIndex) => (
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
    <Content
      style={{ padding: "20px 50px", margin: "0 auto", maxWidth: "1200px" }}
    >
      <Button
        icon={<ArrowLeftOutlined />}
        onClick={() => navigate("/history")} // Or navigate(-1) if appropriate
        style={{ marginBottom: 20 }}
      >
        Back to Submission History
      </Button>

      <Title level={2}>
        <ProfileOutlined /> Analysis Results
      </Title>
      <Text type="secondary">Submission ID: {submissionId}</Text>

      {summary && (
        <Card
          title={
            <>
              <InfoCircleOutlined /> Overall Summary
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

      <Title level={3} style={{ marginTop: 30 }}>
        <FileTextOutlined /> Detailed Findings by File
      </Title>
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
        <TabPane
          tab={
            <>
              <CodeOutlined /> SARIF Report (JSON)
            </>
          }
          key="sarif"
        >
          <Card title="SARIF Output">
            <pre style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {sarif_report
                ? JSON.stringify(sarif_report, null, 2)
                : "SARIF report not available."}
            </pre>
          </Card>
        </TabPane>
        {/* <TabPane tab="Raw JSON" key="raw">
           <Card title="Raw Analysis JSON">
            <pre style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {result ? JSON.stringify(result, null, 2) : 'Raw JSON not available.'}
            </pre>
          </Card>
        </TabPane> */}
      </Tabs>
    </Content>
  );
};

export default ResultsPage;
