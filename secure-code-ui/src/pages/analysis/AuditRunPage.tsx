import { ArrowLeftOutlined, LoadingOutlined } from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Card,
  Col,
  Collapse,
  Descriptions,
  Empty,
  Layout,
  Row,
  Select,
  Space,
  Spin,
  Tag,
  Typography,
} from "antd";
import React, { useEffect, useMemo, useState } from "react";
import ReactDiffViewer from 'react-diff-viewer-continued';
import { useNavigate, useParams } from "react-router-dom";
import ResultsFileTree from "../../features/results-display/components/ResultsFileTree";
import ScanSummary from '../../features/results-display/components/ScanSummary';
import { scanService } from "../../shared/api/scanService";
import { SeverityColors } from "../../shared/lib/severityMappings";
import { type Finding, type ScanResultResponse } from "../../shared/types/api";

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

const AuditRunPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [sortOrder, setSortOrder] = useState<SortOption>("severity");

  const {
    data: result,
    isLoading,
    isError,
    error,
  } = useQuery<ScanResultResponse, Error>({
    queryKey: ["scanResult", scanId],
    queryFn: () => {
      if (!scanId) throw new Error("Scan ID is missing");
      return scanService.getScanResult(scanId);
    },
    enabled: !!scanId,
  });

  const allFindings = useMemo(
    () => result?.summary_report?.files_analyzed?.flatMap((file) => file.findings) || [],
    [result]
  );

  const findingsForSelectedFile = useMemo(() => {
    if (!selectedFilePath) return [];
    const findings = allFindings.filter(f => f.file_path === selectedFilePath);

    return [...findings].sort((a, b) => {
      switch (sortOrder) {
        case "line":
          return (a.line_number || 0) - (b.line_number || 0);
        case "cwe":
          return (a.cwe || "").localeCompare(b.cwe || "");
        case "severity":
        default:
          return (SEVERITY_ORDER[b.severity?.toUpperCase() || "NONE"] || 0) -
                 (SEVERITY_ORDER[a.severity?.toUpperCase() || "NONE"] || 0);
      }
    });
  }, [allFindings, selectedFilePath, sortOrder]);

  useEffect(() => {
    if (allFindings.length > 0 && !selectedFilePath) {
      setSelectedFilePath(allFindings[0].file_path);
    }
  }, [allFindings, selectedFilePath]);

  if (isLoading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh" }}>
        <Spin indicator={<LoadingOutlined style={{ fontSize: 48 }} spin />} tip="Loading Audit Report..." />
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

  if (!result || !result.summary_report) {
    return (
      <Content style={{ padding: "20px", textAlign: "center" }}>
        <Empty description="No analysis results found for this scan." />
        <Button onClick={() => navigate(-1)} style={{ marginTop: 24 }}>
            <ArrowLeftOutlined /> Back to History
        </Button>
      </Content>
    );
  }

  const { summary_report } = result;

  return (
    <Layout style={{ background: '#fff', padding: 24 }}>
        <Row justify="space-between" align="middle" style={{ marginBottom: 16 }}>
            <Col>
                <Title level={3} style={{ margin: 0 }}>Audit Report: {summary_report.project_name}</Title>
                <Text copyable type="secondary" code>Scan ID: {scanId}</Text>
            </Col>
             <Col>
                <Button onClick={() => navigate("/account/history")} icon={<ArrowLeftOutlined />}>
                    Back to History
                </Button>
            </Col>
        </Row>

        <ScanSummary summaryReport={summary_report} />
      
        <Layout style={{ background: '#fff' }}>
            <Sider width={350} style={{ background: "#f0f2f5", borderRight: "1px solid #d9d9d9", padding: "16px", overflow: "auto" }}>
                <Title level={5} style={{ marginTop: 0, marginBottom: 16 }}>Analyzed Files</Title>
                <ResultsFileTree
                  analyzedFiles={summary_report.files_analyzed || []}
                  findings={allFindings}
                  onSelect={(keys) => {
                      const newPath = keys[0] as string;
                      if (newPath) {
                          setSelectedFilePath(newPath);
                          setSelectedFinding(null); // Reset finding selection when file changes
                      }
                  }}
                />
            </Sider>
            <Content style={{ padding: '0 24px', minHeight: 280, display: 'flex', flexDirection: 'column' }}>
                <Row justify="space-between" align="middle" style={{ marginBottom: 16 }}>
                    <Col><Title level={5} style={{ margin: 0 }}>{findingsForSelectedFile.length} findings in {selectedFilePath || '...'}</Title></Col>
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
                <div style={{ flex: '1 1 auto', overflowY: 'auto', paddingRight: '8px' }}>
                    {findingsForSelectedFile.length > 0 ? (
                        <Collapse accordion onChange={(key) => {
                            const findingId = Array.isArray(key) ? key[0] : key;
                            setSelectedFinding(findingsForSelectedFile.find(f => f.id.toString() === findingId) || null)
                        }}>
                            {findingsForSelectedFile.map((finding) => (
                                <Panel
                                    key={finding.id}
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
                                </Panel>
                            ))}
                        </Collapse>
                    ) : (
                    <Empty description="Select a file to see findings." style={{marginTop: 48}}/>
                    )}
                </div>
                 {selectedFinding && selectedFinding.fixes?.[0]?.original_snippet && (
                    <Card size="small" title="Suggested Fix" style={{ marginTop: 16, flexShrink: 0 }}>
                        <ReactDiffViewer 
                            oldValue={selectedFinding.fixes[0].original_snippet} 
                            newValue={selectedFinding.fixes[0].suggested_fix} 
                            splitView={false} 
                            hideLineNumbers={true}
                            useDarkTheme={true}
                        />
                    </Card>
                )}
            </Content>
        </Layout>
    </Layout>
  );
};

export default AuditRunPage;