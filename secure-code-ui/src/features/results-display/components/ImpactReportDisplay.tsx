// src/app/components/ImpactReportDisplay.tsx

import { BarChartOutlined, BuildOutlined, InfoCircleOutlined, ToolOutlined } from '@ant-design/icons';
import { Card, Descriptions, Divider, List, Space, Tag, Typography } from 'antd';
import React from 'react';
import type { ImpactReport } from "../../../shared/types/api";

const { Title, Paragraph, Text } = Typography;

interface ImpactReportDisplayProps {
  report: ImpactReport;
}

const ImpactReportDisplay: React.FC<ImpactReportDisplayProps> = ({ report }) => {
  return (
    <Card
      title={
        <Space>
          <InfoCircleOutlined />
          <Title level={4} style={{ margin: 0 }}>AI-Generated Impact Report</Title>
        </Space>
      }
      style={{ marginBottom: '24px' }}
      headStyle={{ backgroundColor: '#f0f2f5' }}
    >
      <Paragraph style={{ fontSize: '16px' }}>
        {report.executive_summary}
      </Paragraph>
      <Divider />
      <Descriptions bordered column={1} size="small">
        <Descriptions.Item 
          label={<><BarChartOutlined /> Vulnerability Categories</>}
        >
          {report.vulnerability_categories.length > 0 ? 
            report.vulnerability_categories.map((cat, index) => <Tag key={index} color="blue">{cat}</Tag>) :
            <Text type="secondary">No specific categories highlighted.</Text>
          }
        </Descriptions.Item>
        <Descriptions.Item 
          label={<><ToolOutlined /> Estimated Remediation Effort</>}
        >
          <Text strong>{report.estimated_remediation_effort}</Text>
        </Descriptions.Item>
        <Descriptions.Item 
          label={<><BuildOutlined /> Required Architectural Changes</>}
        >
          {report.required_architectural_changes.length > 0 ? (
            <List
              size="small"
              dataSource={report.required_architectural_changes}
              renderItem={(item) => <List.Item>{item}</List.Item>}
            />
          ) : (
            <Text type="secondary">No major architectural changes are required.</Text>
          )}
        </Descriptions.Item>
      </Descriptions>
    </Card>
  );
};

export default ImpactReportDisplay;