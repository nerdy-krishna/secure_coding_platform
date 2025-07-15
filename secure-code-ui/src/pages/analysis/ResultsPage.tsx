// src/pages/analysis/ResultsPage.tsx
import {
  ArrowLeftOutlined,
  CodeOutlined,
  FilePdfOutlined,
  LoadingOutlined,
  MinusSquareOutlined,
  PlusSquareOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Card,
  Col,
  Divider,
  Empty,
  Layout,
  Row,
  Select,
  Space,
  Spin,
  Tag,
  Typography,
  message,
} from "antd";
import { saveAs } from "file-saver";
import React, { useEffect, useMemo, useState } from "react";
import ReactDiffViewer from "react-diff-viewer-continued";
import { Link, useNavigate, useParams } from "react-router-dom";
import FindingList from "../../features/results-display/components/FindingList";
import ResultsFileTree from "../../features/results-display/components/ResultsFileTree";
import ScanSummary from "../../features/results-display/components/ScanSummary";
import { scanService } from "../../shared/api/scanService";
import type { Finding, ScanResultResponse } from "../../shared/types/api";

const { Content, Sider } = Layout;
const { Title, Paragraph } = Typography;
const { Option } = Select;

type GroupableFields = keyof Pick<Finding, 'severity' | 'confidence' | 'cwe' | 'agent_name'>;

const ResultsPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
  const [activeFindingKeys, setActiveFindingKeys] = useState<string[]>([]);
  const [sortConfig, setSortConfig] = useState<{ field: keyof Finding; order: 'asc' | 'desc' }>({ field: 'severity', order: 'desc' });
  const [filters, setFilters] = useState<Partial<Record<keyof Finding, string[]>>>({});
  const [groupBy, setGroupBy] = useState<GroupableFields | 'none'>('severity');

  const { data: result, isLoading, isError, error, refetch } = useQuery<ScanResultResponse, Error>({
    queryKey: ["scanResult", scanId],
    queryFn: () => {
      if (!scanId) throw new Error("Scan ID is missing");
      return scanService.getScanResult(scanId);
    },
    enabled: !!scanId,
    refetchOnWindowFocus: false,
  });

  // --- ADD THIS LOGGING BLOCK ---
    useEffect(() => {
        if (result) {
            console.log("--- [ResultsPage] Data Received from API ---");
            console.log(result);
            console.log("-------------------------------------------");
        }
    }, [result]);
  // --- END LOGGING BLOCK ---

  const applyFixesMutation = useMutation({
    mutationFn: (findingIds: number[]) => scanService.applySelectiveFixes(scanId!, findingIds),
    onSuccess: (data) => {
      message.success(data.message || "Remediation process initiated.");
      refetch();
    },
    onError: (err: Error) => message.error(`Failed to apply fixes: ${err.message}`),
  });

  const allFindings = useMemo(() => result?.summary_report?.files_analyzed?.flatMap(f => f.findings) || [], [result]);

  const uniqueFilterOptions = useMemo(() => {
    return {
      severity: [...new Set(allFindings.map(f => f.severity).filter(Boolean))],
      confidence: [...new Set(allFindings.map(f => f.confidence).filter(Boolean))],
      cwe: [...new Set(allFindings.map(f => f.cwe).filter(Boolean))],
      agent_name: [...new Set(allFindings.map(f => f.agent_name).filter(Boolean))],
    };
  }, [allFindings]);

  const processedFindings = useMemo(() => {
    if (!selectedFilePath || !result?.summary_report?.files_analyzed) return [];
    
    let findings = result.summary_report.files_analyzed.find(f => f.file_path === selectedFilePath)?.findings || [];

    // Apply Filters
    findings = findings.filter(finding => {
      return Object.entries(filters).every(([key, values]) => {
        if (!values || values.length === 0) return true;
        const findingValue = finding[key as keyof Finding];
        return findingValue ? values.includes(findingValue as string) : false;
      });
    });

    // Apply Sorting
    const severityOrder: Record<string, number> = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFORMATIONAL': 1 };
    findings.sort((a, b) => {
      const field = sortConfig.field;
      let valA = a[field];
      let valB = b[field];

      if (field === 'severity') {
        valA = severityOrder[a.severity.toUpperCase()] || 0;
        valB = severityOrder[b.severity.toUpperCase()] || 0;
      }

      if (valA === undefined || valA === null) return 1;
      if (valB === undefined || valB === null) return -1;
      
      let comparison = 0;
      if (typeof valA === 'string' && typeof valB === 'string') {
        comparison = valA.localeCompare(valB);
      } else if (typeof valA === 'number' && typeof valB === 'number') {
        comparison = valA - valB;
      }
      
      return sortConfig.order === 'asc' ? comparison : -comparison;
    });

    return findings;
  }, [result, selectedFilePath, sortConfig, filters]);

  const groupedAndSortedFindings = useMemo(() => {
    if (groupBy === 'none') {
      return { 'all': processedFindings };
    }
    return processedFindings.reduce((acc, finding) => {
      const key = finding[groupBy] || 'Unknown';
      if (!acc[key]) {
        acc[key] = [];
      }
      acc[key].push(finding);
      return acc;
    }, {} as Record<string, Finding[]>);
  }, [processedFindings, groupBy]);


  useEffect(() => {
    const filesWithFindings = result?.summary_report?.files_analyzed?.filter(f => f.findings.length > 0) || [];
    if (!selectedFilePath && filesWithFindings.length > 0) {
        setSelectedFilePath(filesWithFindings[0].file_path);
    }
  }, [result, selectedFilePath]);

  const handleDownloadSarif = () => {
    if (result?.sarif_report) {
      const sarifString = JSON.stringify(result.sarif_report, null, 2);
      const blob = new Blob([sarifString], { type: "application/sarif+json;charset=utf-8" });
      saveAs(blob, `scan-report-${scanId}.sarif`);
    }
  };

  if (isLoading) return <Spin indicator={<LoadingOutlined style={{ fontSize: 48 }} spin />} tip="Loading Report..." style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh" }} />;
  if (isError) return <Alert message="Error" description={error.message} type="error" showIcon />;
  if (!result || !result.summary_report) return <Empty description="No analysis results found for this scan." />;

  const { summary_report, status, original_code_map, fixed_code_map } = result;
  const isRemediationComplete = status === 'REMEDIATION_COMPLETED';

  const originalCode = original_code_map?.[selectedFilePath || ""] || "";
  const fixedCode = fixed_code_map?.[selectedFilePath || ""] || "";
  
  return (
    <Layout style={{ background: 'transparent' }}>
      <Row justify="space-between" align="middle" style={{ marginBottom: 16 }}>
        <Col>
            <Title level={3} style={{ margin: 0 }}>{summary_report.scan_type.replace(/_/g, ' ')} Report: {summary_report.project_name}</Title>
            <Paragraph copyable type="secondary" style={{margin: 0}}>Scan ID: {scanId}</Paragraph>
            <Paragraph copyable type="secondary" style={{margin: 0}}>Project ID: {summary_report.project_id}</Paragraph>
        </Col>
        <Col>
            <Space>
                {result?.impact_report && <Link to={`/scans/${scanId}/executive-summary`}><Button icon={<FilePdfOutlined />}>Executive Summary</Button></Link>}
                {result?.sarif_report && <Button icon={<CodeOutlined />} onClick={handleDownloadSarif}>Download SARIF</Button>}
                <Button onClick={() => navigate("/account/history")} icon={<ArrowLeftOutlined />}>Back to History</Button>
            </Space>
        </Col>
      </Row>
      
      <ScanSummary summaryReport={summary_report} />

      <Layout style={{ background: '#fff', marginTop: 24, borderRadius: 8, border: '1px solid #f0f0f0', flexDirection: 'column' }}>
        <Layout>
            <Sider width={350} style={{ background: "#fafafa", padding: "16px", overflow: "auto", borderRight: '1px solid #f0f0f0', borderRadius: '8px 0 0 8px' }}>
              <Title level={5} style={{ marginTop: 0, marginBottom: 16 }}>Analyzed Files</Title>
              <ResultsFileTree
                analyzedFiles={summary_report.files_analyzed || []}
                findings={allFindings}
                selectedKeys={selectedFilePath ? [selectedFilePath] : []}
                onSelect={(keys) => {
                    setSelectedFilePath(keys[0] as string);
                }}
              />
            </Sider>
            <Content style={{ padding: '16px 24px', minHeight: 400, display: 'flex', flexDirection: 'column' }}>
                <Row justify="space-between" align="middle" style={{ marginBottom: 16, flexWrap: 'wrap', gap: '10px' }}>
                    <Title level={5} style={{ margin: 0 }}>Findings in: {selectedFilePath || "..."}</Title>
                    <Space wrap>
                        <Button size="small" onClick={() => setActiveFindingKeys(processedFindings.map(f => f.id.toString()))} icon={<PlusSquareOutlined />}>Expand All</Button>
                        <Button size="small" onClick={() => setActiveFindingKeys([])} icon={<MinusSquareOutlined />}>Collapse All</Button>
                    </Space>
                </Row>
                
                <Card size="small" style={{ marginBottom: 16 }}>
                    <Row gutter={[16, 16]} align="bottom">
                        <Col xs={24} sm={12} md={8}>
                            <Typography.Text>Group By:</Typography.Text>
                            <Select
                                value={groupBy}
                                onChange={(value) => setGroupBy(value)}
                                style={{ width: '100%' }}
                            >
                                <Option value="none">None</Option>
                                <Option value="severity">Severity</Option>
                                <Option value="confidence">Confidence</Option>
                                <Option value="cwe">CWE</Option>
                                <Option value="agent_name">Agent</Option>
                            </Select>
                        </Col>
                        <Col xs={24} sm={12} md={8}>
                            <Typography.Text>Sort By:</Typography.Text>
                            <Select
                                value={sortConfig.field}
                                onChange={(field) => setSortConfig(prev => ({ ...prev, field }))}
                                style={{ width: '100%' }}
                            >
                                <Option value="severity">Severity</Option>
                                <Option value="confidence">Confidence</Option>
                                <Option value="line_number">Line Number</Option>
                                <Option value="cwe">CWE</Option>
                                <Option value="agent_name">Agent</Option>
                            </Select>
                        </Col>
                        <Col xs={24} sm={12} md={8}>
                             <Typography.Text>Order:</Typography.Text>
                            <Select
                                value={sortConfig.order}
                                onChange={(order) => setSortConfig(prev => ({ ...prev, order }))}
                                style={{ width: '100%' }}
                            >
                                <Option value="desc">Descending</Option>
                                <Option value="asc">Ascending</Option>
                            </Select>
                        </Col>
                         <Col xs={24} sm={12} md={24}>
                             <Typography.Text>Filter by Severity:</Typography.Text>
                            <Select
                                mode="multiple"
                                allowClear
                                style={{ width: '100%' }}
                                placeholder="Filter by Severity"
                                onChange={(values) => setFilters(prev => ({...prev, severity: values}))}
                            >
                                {uniqueFilterOptions.severity.map(s => <Option key={s} value={s}>{s}</Option>)}
                            </Select>
                        </Col>
                    </Row>
                </Card>

                <div style={{ flexGrow: 1, overflowY: 'auto' }}>
                    {Object.entries(groupedAndSortedFindings).map(([groupName, findingsInGroup]) => (
                      <React.Fragment key={groupName}>
                        {groupBy !== 'none' && (
                          <Divider orientation="left">
                             <Tag color="purple">{`${groupBy.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}: ${groupName}`}</Tag>
                          </Divider>
                        )}
                        <FindingList 
                            findings={findingsInGroup} 
                            onRemediateFinding={(id) => applyFixesMutation.mutate([id])}
                            activeKeys={activeFindingKeys}
                            onActiveKeyChange={(keys) => setActiveFindingKeys(keys as string[])}
                        />
                      </React.Fragment>
                    ))}
                </div>
            </Content>
        </Layout>

        {isRemediationComplete && selectedFilePath && (
          <div style={{ padding: '0 24px 24px 24px' }}>
            <ReactDiffViewer oldValue={originalCode} newValue={fixedCode} splitView={true} useDarkTheme={false} />
          </div>
        )}
      </Layout>
    </Layout>
  );
};

export default ResultsPage;