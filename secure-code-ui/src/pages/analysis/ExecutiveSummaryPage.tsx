// secure-code-ui/src/pages/analysis/ExecutiveSummaryPage.tsx

import {
  ArrowLeftOutlined,
  BuildOutlined,
  FilePdfOutlined,
  InfoCircleOutlined,
  SafetyCertificateOutlined,
  ToolOutlined,
  UnorderedListOutlined,
} from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Divider,
  List,
  Space,
  Spin,
  Tag,
  Typography,
  message,
} from 'antd';
import { saveAs } from 'file-saver';
import React, { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import apiClient from '../../shared/api/apiClient';
import { scanService } from '../../shared/api/scanService';

const { Title, Paragraph, Text } = Typography;

const ExecutiveSummaryPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const [isDownloading, setIsDownloading] = useState(false);

  const {
    data: result,
    isLoading,
    isError,
    error,
  } = useQuery({
    queryKey: ["scanResult", scanId],
    queryFn: () => {
      if (!scanId) {
        throw new Error('Submission ID is required');
      }
      return scanService.getScanResult(scanId);
    },
    enabled: !!scanId, // Only run query if submissionId is present
  });

  if (isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <Spin size="large" tip="Loading Executive Summary..." />
      </div>
    );
  }

  if (isError) {
    return (
      <Alert
        message="Error"
        description={`Failed to load report: ${error.message}`}
        type="error"
        showIcon
        style={{ margin: '20px' }}
      />
    );
  }

  if (!result || !result.impact_report) {
    return (
      <Alert
        message="Report Not Found"
        description="The executive summary for this submission could not be found."
        type="warning"
        showIcon
        style={{ margin: '20px' }}
      />
    );
  }

  const handleDownload = async () => {
    if (!scanId) return;
    setIsDownloading(true);
    try {
      const response = await apiClient.get(
        `/scans/${scanId}/executive-summary/download`,
        { responseType: 'blob' } // Important: expect binary data
      );
      saveAs(response.data, `executive-summary-${scanId}.pdf`);
    } catch (err) {
      console.error("PDF Download failed", err);
      message.error("Could not download the report. Please try again.");
    } finally {
      setIsDownloading(false);
    }
  };

  const { impact_report, summary_report } = result;
  return (
    <div style={{ maxWidth: '960px', margin: '0 auto', padding: '24px' }}>
      <Space direction="vertical" style={{ width: '100%' }} size="large">
        <Link to={`/analysis/results/${scanId}`}>
          <Button icon={<ArrowLeftOutlined />}>Back to Full Report</Button>
        </Link>

        <Card>
          <Title level={2} style={{ textAlign: 'center', marginBottom: '8px' }}>
            Executive Security Summary
          </Title>
          <Paragraph style={{ textAlign: 'center' }} type="secondary">
            Project: {summary_report?.project_name || 'N/A'} | Submission ID: {scanId}
          </Paragraph>
          <Divider />

          <Descriptions bordered column={1} size="small" style={{ marginBottom: 24 }}>
            <Descriptions.Item label={<><InfoCircleOutlined /> Executive Overview</>}>
              <Paragraph style={{ margin: 0 }}>{impact_report.executive_summary}</Paragraph>
            </Descriptions.Item>
          </Descriptions>

          <Title level={4}><UnorderedListOutlined /> Vulnerability Analysis</Title>
          <Paragraph>{impact_report.vulnerability_overview}</Paragraph>

          <Title level={4}><SafetyCertificateOutlined /> High-Risk Findings</Title>
          <List
            size="small"
            bordered
            dataSource={impact_report.high_risk_findings_summary}
            renderItem={(item) => <List.Item>{item}</List.Item>}
            style={{ marginBottom: 24 }}
          />

          <Title level={4}><ToolOutlined /> Remediation Strategy</Title>
          <Paragraph>{impact_report.remediation_strategy}</Paragraph>
          
          <Descriptions layout="vertical" bordered>
             <Descriptions.Item label={<><BuildOutlined /> Architectural Changes Required</>}>
                {impact_report.required_architectural_changes.length > 0 && impact_report.required_architectural_changes[0] !== 'None' ? (
                     <List
                        size="small"
                        dataSource={impact_report.required_architectural_changes}
                        renderItem={(item) => <List.Item>{item}</List.Item>}
                    />
                ) : (
                    <Text type="secondary">None</Text>
                )}
            </Descriptions.Item>
            <Descriptions.Item label="Estimated Effort">
                <Tag color="orange" style={{fontSize: '14px', padding: '4px 8px'}}>{impact_report.estimated_remediation_effort}</Tag>
            </Descriptions.Item>
             <Descriptions.Item label="Vulnerability Categories">
                 <Space wrap>
                    {impact_report.vulnerability_categories.map((cat, index) => <Tag key={index} color="blue">{cat}</Tag>)}
                 </Space>
            </Descriptions.Item>
          </Descriptions>

          <Divider />
          <div style={{ textAlign: 'center' }}>
            <Button 
              type="primary" 
              icon={<FilePdfOutlined />} 
              size="large"
              onClick={handleDownload}
              loading={isDownloading}
            >
              Download as PDF
            </Button>
          </div>
        </Card>
      </Space>
    </div>
  );
};

export default ExecutiveSummaryPage;