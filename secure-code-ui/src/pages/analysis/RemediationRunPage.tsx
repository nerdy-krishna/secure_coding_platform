import {
  ArrowLeftOutlined,
  LoadingOutlined,
} from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Card,
  Col,
  Empty,
  Layout,
  Row,
  Spin,
  Typography,
} from "antd";
import React, { useEffect, useState } from "react";
import ReactDiffViewer from "react-diff-viewer-continued";
import { useNavigate, useParams } from "react-router-dom";
import ResultsFileTree from "../../features/results-display/components/ResultsFileTree";
import ScanSummary from "../../features/results-display/components/ScanSummary";
import { scanService } from "../../shared/api/scanService";
import { type ScanResultResponse } from "../../shared/types/api";

const { Content, Sider } = Layout;
const { Title, Text } = Typography;

const RemediationRunPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);

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
  
  const allFindings = result?.summary_report?.files_analyzed?.flatMap((file) => file.findings) || [];

  const originalCode = result?.original_code_map?.[selectedFilePath || ""] || "";
  const fixedCode = result?.fixed_code_map?.[selectedFilePath || ""] || "";

  useEffect(() => {
    if (result && !selectedFilePath) {
      const firstFileWithChanges = result.summary_report?.files_analyzed?.[0]?.file_path;
      setSelectedFilePath(firstFileWithChanges || null);
    }
  }, [result, selectedFilePath]);

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

  if (!result || !result.summary_report || !result.original_code_map || !result.fixed_code_map) {
    return (
      <Content style={{ padding: "20px", textAlign: "center" }}>
        <Empty description="No remediation results found for this scan." />
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
              <Title level={3} style={{ margin: 0 }}>Remediation Report: {summary_report.project_name}</Title>
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
          <Title level={5} style={{ marginTop: 0, marginBottom: 16 }}>Remediated Files</Title>
          <ResultsFileTree
            analyzedFiles={summary_report.files_analyzed || []}
            findings={allFindings}
            onSelect={(keys) => setSelectedFilePath(keys[0] as string)}
          />
        </Sider>
        <Content style={{ padding: '0 24px', minHeight: 280, display: 'flex', flexDirection: 'column' }}>
            <Card title={`Code Diff for: ${selectedFilePath || '...'}`}>
                {selectedFilePath ? (
                    <div style={{ flex: '1 1 auto', overflowY: 'auto' }}>
                        <ReactDiffViewer 
                            oldValue={originalCode} 
                            newValue={fixedCode} 
                            splitView={true} 
                            useDarkTheme={true} 
                        />
                    </div>
                ) : (
                    <Empty description="Select a file to view code changes." />
                )}
            </Card>
        </Content>
      </Layout>
    </Layout>
  );
};

export default RemediationRunPage;