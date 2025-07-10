// src/pages/analysis/RemediationRunPage.tsx
import {
  ArrowLeftOutlined,
  CheckCircleOutlined,
  CodeOutlined,
  LoadingOutlined,
} from "@ant-design/icons";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Card,
  Col,
  Collapse,
  Empty,
  Layout,
  Row,
  Spin,
  Typography,
  message,
} from "antd";
import React, { useMemo, useState } from "react";
import ReactDiffViewer from "react-diff-viewer-continued";
import { useNavigate, useParams } from "react-router-dom";
import ResultsFileTree from "../../features/results-display/components/ResultsFileTree";
import ScanSummary from "../../features/results-display/components/ScanSummary";
import { scanService } from "../../shared/api/scanService";
import type { Finding, ScanResultResponse } from "../../shared/types/api";

const { Content, Sider } = Layout;
const { Title, Text, Paragraph } = Typography;
const { Panel } = Collapse;

// Component to display the list of findings with individual diffs
const AuditAndRemediateView: React.FC<{
  result: ScanResultResponse;
  scanId: string;
}> = ({ result, scanId }) => {
  const queryClient = useQueryClient();
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);

  const allFindings = useMemo(
    () => result.summary_report?.files_analyzed?.flatMap((file) => file.findings) || [],
    [result]
  );
  
  const findingsForSelectedFile = useMemo(
    () => allFindings.filter((f) => f.file_path === selectedFilePath),
    [allFindings, selectedFilePath]
  );
  
  const applyFixesMutation = useMutation({
    mutationFn: () => scanService.applyAllFixes(scanId),
    onSuccess: (data) => {
      message.success(data.message || "Fixes are being applied. The page will refresh.");
      queryClient.invalidateQueries({ queryKey: ["scanResult", scanId] });
    },
    onError: (error) => {
      message.error(`Failed to apply fixes: ${error.message}`);
    }
  });

  return (
    <>
      <Row justify="end" style={{ marginBottom: 16 }}>
        <Button
          type="primary"
          icon={<CheckCircleOutlined />}
          size="large"
          loading={applyFixesMutation.isPending}
          onClick={() => applyFixesMutation.mutate()}
        >
          Apply All Fixes & Remediate Codebase
        </Button>
      </Row>
      <Layout style={{ background: '#fff' }}>
        <Sider width={350} style={{ background: "#f0f2f5", padding: "16px", overflow: "auto" }}>
          <Title level={5} style={{ marginTop: 0, marginBottom: 16 }}>Analyzed Files</Title>
          <ResultsFileTree
            analyzedFiles={result.summary_report?.files_analyzed || []}
            findings={allFindings}
            onSelect={(keys) => setSelectedFilePath(keys[0] as string)}
          />
        </Sider>
        <Content style={{ padding: '0 24px', minHeight: 280, maxHeight: '70vh', overflowY: 'auto' }}>
            {findingsForSelectedFile.length > 0 ? (
                <Collapse accordion>
                    {findingsForSelectedFile.map((finding: Finding) => (
                        <Panel header={`${finding.severity}: ${finding.title}`} key={finding.id}>
                            <Paragraph>{finding.description}</Paragraph>
                            {finding.fixes && finding.fixes[0] ? (
                                <ReactDiffViewer
                                    oldValue={finding.fixes[0].original_snippet || ''}
                                    newValue={finding.fixes[0].suggested_fix || ''}
                                    splitView={false}
                                    hideLineNumbers={true}
                                    useDarkTheme={true}
                                />
                            ) : <Text type="secondary">No code fix suggested for this finding.</Text>}
                        </Panel>
                    ))}
                </Collapse>
            ) : (
                <Empty description="Select a file with findings to view suggested fixes." />
            )}
        </Content>
      </Layout>
    </>
  );
};

// Component to display the final side-by-side diff
const RemediateCompleteView: React.FC<{ result: ScanResultResponse }> = ({ result }) => {
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);

  const originalCode = result.original_code_map?.[selectedFilePath || ""] || "";
  const fixedCode = result.fixed_code_map?.[selectedFilePath || ""] || "";
  
  const filesWithChanges = useMemo(() =>
    result.summary_report?.files_analyzed?.filter(f => f.findings.length > 0) || [],
    [result]
  );
  
  return (
      <Layout style={{ background: '#fff' }}>
        <Sider width={350} style={{ background: "#f0f2f5", padding: "16px", overflow: "auto" }}>
          <Title level={5} style={{ marginTop: 0, marginBottom: 16 }}>Remediated Files</Title>
          <ResultsFileTree
            analyzedFiles={filesWithChanges}
            findings={result.summary_report?.files_analyzed?.flatMap(f => f.findings) || []}
            onSelect={(keys) => setSelectedFilePath(keys[0] as string)}
          />
        </Sider>
        <Content style={{ padding: '0 24px', minHeight: 280 }}>
            <Card title={<><CodeOutlined /> Code Diff for: {selectedFilePath || '...'}</>}>
                {selectedFilePath ? (
                    <ReactDiffViewer
                        oldValue={originalCode}
                        newValue={fixedCode}
                        splitView={true}
                        useDarkTheme={true}
                    />
                ) : (
                    <Empty description="Select a file to view the changes." />
                )}
            </Card>
        </Content>
      </Layout>
  )
};

const RemediationRunPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();

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
    refetchInterval: (query) => {
        // Refetch if the scan is still running
        const data = query.state.data;
        if (data && data.status !== 'COMPLETED' && data.status !== 'REMEDIATION_COMPLETED' && data.status !== 'FAILED') {
            return 5000;
        }
        return false;
    }
  });

  if (isLoading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh" }}>
        <Spin indicator={<LoadingOutlined style={{ fontSize: 48 }} spin />} tip="Loading Remediation Report..." />
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
        <Empty description="No remediation results found for this scan." />
        <Button onClick={() => navigate(-1)} style={{ marginTop: 24 }}>
            <ArrowLeftOutlined /> Back to History
        </Button>
      </Content>
    );
  }
  
  const scanType = result.summary_report.scan_type;
  const status = result.status;
  const pageTitle = scanType === 'AUDIT_AND_REMEDIATE' ? 'Audit & Remediate Report' : 'Direct Remediation Report';

  return (
    <Layout style={{ background: '#fff', padding: 24 }}>
      <Row justify="space-between" align="middle" style={{ marginBottom: 16 }}>
          <Col>
              <Title level={3} style={{ margin: 0 }}>{pageTitle}: {result.summary_report.project_name}</Title>
              <Text copyable type="secondary" code>Scan ID: {scanId}</Text>
          </Col>
           <Col>
              <Button onClick={() => navigate("/account/history")} icon={<ArrowLeftOutlined />}>
                  Back to History
              </Button>
          </Col>
      </Row>

      <ScanSummary summaryReport={result.summary_report} />
      
      {status === 'REMEDIATION_COMPLETED' && <RemediateCompleteView result={result} />}
      
      {scanType === 'AUDIT_AND_REMEDIATE' && status === 'COMPLETED' && <AuditAndRemediateView result={result} scanId={scanId!} />}
      
      {status !== 'REMEDIATION_COMPLETED' && status !== 'COMPLETED' &&
        <Card>
            <Spin tip={`Scan in progress... Status: ${status}`} />
        </Card>
      }
    </Layout>
  );
};

export default RemediationRunPage;