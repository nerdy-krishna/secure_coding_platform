// src/pages/analysis/ResultsPage.tsx
import {
  ArrowLeftOutlined,
  CheckCircleOutlined,
  CodeOutlined,
  FilePdfOutlined,
  LoadingOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Col,
  Empty,
  Layout,
  Row,
  Space,
  Spin,
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
import type { ScanResultResponse } from "../../shared/types/api";

const { Content, Sider } = Layout;
const { Title, Paragraph } = Typography;

const ResultsPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
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

  const analyzedFilesWithFindings = useMemo(
    () => result?.summary_report?.files_analyzed?.filter(f => f.findings.length > 0) || [],
    [result]
  );
  
  const allFindings = useMemo(() => result?.summary_report?.files_analyzed?.flatMap(f => f.findings) || [], [result]);

  // FIX: Get findings directly from the selected file object to prevent path mismatch issues.
  const findingsForSelectedFile = useMemo(() => {
    if (!selectedFilePath || !result?.summary_report?.files_analyzed) return [];
    const selectedFile = result.summary_report.files_analyzed.find(f => f.file_path === selectedFilePath);
    return selectedFile?.findings || [];
  }, [result, selectedFilePath]);

  // FIX: Auto-select the first file that has findings on page load.
  useEffect(() => {
    if (!selectedFilePath && analyzedFilesWithFindings.length > 0) {
        setSelectedFilePath(analyzedFilesWithFindings[0].file_path);
    }
  }, [selectedFilePath, analyzedFilesWithFindings]);


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
  const isAuditAndRemediate = summary_report.scan_type === 'AUDIT_AND_REMEDIATE';
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
                findings={summary_report.files_analyzed?.flatMap(f => f.findings) || []}
                selectedKeys={selectedFilePath ? [selectedFilePath] : []}
                onSelect={(keys) => {
                    setSelectedFilePath(keys[0] as string);
                }}
              />
            </Sider>
            <Content style={{ padding: '16px 24px', minHeight: 400, display: 'flex', flexDirection: 'column' }}>
                <Row justify="space-between" align="middle">
                    <Title level={5}>Findings in: {selectedFilePath || "..."}</Title>
                    {isAuditAndRemediate && !isRemediationComplete && findingsForSelectedFile.length > 0 && (
                        <Space>
                            <Button onClick={() => applyFixesMutation.mutate(findingsForSelectedFile.map(f => f.id))} icon={<CheckCircleOutlined />}>Fix All in File</Button>
                            <Button type="primary" onClick={() => applyFixesMutation.mutate(allFindings.map(f => f.id))} icon={<CheckCircleOutlined />}>Fix All in Project</Button>
                        </Space>
                    )}
                </Row>
                <div style={{ flexGrow: 1, overflowY: 'auto' }}>
                    <FindingList 
                        findings={findingsForSelectedFile} 
                        onRemediateFinding={(id) => applyFixesMutation.mutate([id])}
                    />
                </div>
            </Content>
        </Layout>

        {/* --- FIX: Corrected Conditional Bottom Panel --- */}
        <div style={{ padding: '0 24px 24px 24px' }}>
            {isRemediationComplete && selectedFilePath && (
                <ReactDiffViewer oldValue={originalCode} newValue={fixedCode} splitView={true} useDarkTheme={false} />
            )}
        </div>
      </Layout>
    </Layout>
  );
};

export default ResultsPage;