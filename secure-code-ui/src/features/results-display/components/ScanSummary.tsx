import { CheckCircleOutlined, FileExclamationOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { Card, Col, Row, Statistic, Typography } from 'antd';
import React from 'react';
import { SeverityColors } from '../../../shared/lib/severityMappings';
import type { SummaryReport } from '../../../shared/types/api';

const { Title } = Typography;

interface ScanSummaryProps {
  summaryReport: SummaryReport;
}

const ScanSummary: React.FC<ScanSummaryProps> = ({ summaryReport }) => {
  const isAudit = summaryReport.scan_type === 'audit';

  return (
    <Card style={{ marginBottom: 24 }}>
       <Title level={4} style={{ marginTop: 0, marginBottom: 16 }}>
        Scan Summary
      </Title>
      <Row gutter={16}>
        <Col span={6}>
          <Statistic 
            title={isAudit ? "Total Findings" : "Findings Remediated"}
            value={summaryReport.summary?.total_findings_count ?? 0}
            prefix={isAudit ? <FileExclamationOutlined /> : <CheckCircleOutlined />}
            valueStyle={isAudit ? {} : {color: SeverityColors.LOW}}
          />
        </Col>
        <Col span={4}>
          <Statistic 
            title="Critical" 
            value={summaryReport.summary?.severity_counts?.CRITICAL ?? 0}
            valueStyle={{ color: SeverityColors.CRITICAL }} 
          />
        </Col>
        <Col span={4}>
          <Statistic 
            title="High" 
            value={summaryReport.summary?.severity_counts?.HIGH ?? 0}
            valueStyle={{ color: SeverityColors.HIGH }}
          />
        </Col>
        <Col span={4}>
           <Statistic 
            title="Medium" 
            value={summaryReport.summary?.severity_counts?.MEDIUM ?? 0}
            valueStyle={{ color: SeverityColors.MEDIUM }}
          />
        </Col>
        <Col span={6}>
          <Statistic 
            title="Overall Risk Score" 
            value={summaryReport.overall_risk_score?.score ?? 0}
            prefix={<SafetyCertificateOutlined />} 
          />
        </Col>
      </Row>
    </Card>
  );
};

export default ScanSummary;