// src/features/results-display/components/FindingList.tsx
import { CheckCircleOutlined } from "@ant-design/icons";
import { Button, Card, Col, Collapse, Empty, Row, Space, Tag, Typography } from "antd";
import React from "react";
import { SeverityColors } from "../../../shared/lib/severityMappings";
import type { Finding } from "../../../shared/types/api";

const { Text, Paragraph } = Typography;
const { Panel } = Collapse;

interface FindingListProps {
  findings: Finding[];
  onFindingSelect: (finding: Finding | null) => void;
  onRemediateFinding: (findingId: number) => void;
}

const FindingList: React.FC<FindingListProps> = ({ findings, onFindingSelect, onRemediateFinding }) => {
  if (findings.length === 0) {
    return <Empty description="No findings in this file." style={{ marginTop: 48 }} />;
  }

  return (
    <Collapse accordion onChange={(key) => {
        const activeKey = Array.isArray(key) ? key[0] : key;
        const findingId = activeKey ? parseInt(activeKey, 10) : null;
        const selected = findingId ? findings.find(f => f.id === findingId) || null : null;
        onFindingSelect(selected);
    }}>
      {findings.map((finding) => (
        <Panel
          key={finding.id}
          header={
            <Row justify="space-between" align="middle">
              <Col>
                <Space>
                    <Tag color={SeverityColors[finding.severity?.toUpperCase() || "DEFAULT"]}>
                        {finding.severity}
                    </Tag>
                    <Text strong>{finding.title}</Text>
                    <Text type="secondary">(CWE-{finding.cwe?.split('-')[1]})</Text>
                </Space>
              </Col>
            </Row>
          }
          extra={
            <Button
                size="small"
                icon={<CheckCircleOutlined />}
                onClick={(e) => {
                    e.stopPropagation(); // Prevent collapse from toggling
                    onRemediateFinding(finding.id);
                }}
            >
                Fix this
            </Button>
          }
        >
          <Paragraph>{finding.description}</Paragraph>
          <Card size="small" title="Remediation Guidance">
            <Paragraph style={{ margin: 0 }}>{finding.remediation}</Paragraph>
          </Card>
        </Panel>
      ))}
    </Collapse>
  );
};

export default FindingList;