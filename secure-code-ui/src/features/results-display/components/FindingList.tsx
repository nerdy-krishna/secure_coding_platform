import { CheckCircleOutlined, RobotOutlined } from "@ant-design/icons";
import { Button, Col, Collapse, Descriptions, Empty, Popconfirm, Row, Space, Tag, Typography, message } from "antd";
import React from "react";
import { SeverityColors } from "../../../shared/lib/severityMappings";
import type { Finding } from "../../../shared/types/api";
import EnhancedDiffViewer from "./EnhancedDiffViewer";
const { Text } = Typography;
const { Panel } = Collapse;

interface FindingListProps {
  findings: Finding[];
  onRemediateFinding: (findingId: number) => void;
  activeKeys: string[];
  onActiveKeyChange: (keys: string | string[]) => void;
}

const FindingList: React.FC<FindingListProps> = ({ findings, onRemediateFinding, activeKeys, onActiveKeyChange }) => {
  if (findings.length === 0) {
    return <Empty description="No findings in this file." style={{ marginTop: 48 }} />;
  }

  return (
    <Collapse activeKey={activeKeys} onChange={(keys) => onActiveKeyChange(keys as string[])}>
      {findings.map((finding) => (
        <Panel
          key={finding.id.toString()}
          header={
            <Row justify="space-between" align="middle" style={{ width: '100%'}}>
              <Col>
                <Space>
                  <Text strong>{finding.title}</Text>
                  <Tag color={SeverityColors[finding.severity?.toUpperCase() || "DEFAULT"]}>
                      {finding.severity}
                  </Tag>
                </Space>
              </Col>
            </Row>
          }
          extra={
            finding.fixes && (
               <Popconfirm
                    title="Apply this fix?"
                    description="This will create a new remediation commit. Are you sure?"
                    onConfirm={(e) => {
                      e?.stopPropagation();
                      onRemediateFinding(finding.id);
                      message.info("Fix application has been initiated.");
                    }}
                    onCancel={(e) => e?.stopPropagation()}
                    okText="Yes, Fix it"
                    cancelText="No"
                  >
                    <Button
                      size="small"
                      icon={<CheckCircleOutlined />}
                      onClick={(e) => e.stopPropagation()}
                    >
                      Fix this
                    </Button>
                </Popconfirm>
            )
          }
        >
            <Descriptions bordered column={2} size="small" labelStyle={{ backgroundColor: '#fafafa' }}>
                <Descriptions.Item label="Severity" span={1}>{finding.severity}</Descriptions.Item>
                <Descriptions.Item label="Confidence" span={1}>{finding.confidence}</Descriptions.Item>
                <Descriptions.Item label="CWE" span={1}>{finding.cwe}</Descriptions.Item>
                <Descriptions.Item label="Agent" span={1}><RobotOutlined style={{marginRight: '8px'}}/>{finding.agent_name || 'Unknown'}</Descriptions.Item>
                <Descriptions.Item label="File Path" span={2}><Text code>{finding.file_path}</Text></Descriptions.Item>
                <Descriptions.Item label="Line Number" span={2}>{finding.line_number}</Descriptions.Item>
                <Descriptions.Item label="Description" span={2}>{finding.description}</Descriptions.Item>
                <Descriptions.Item label="Remediation" span={2}>{finding.remediation}</Descriptions.Item>
                 {finding.references && finding.references.length > 0 && (
                    <Descriptions.Item label="References" span={2}>
                        <ul style={{paddingLeft: 20, margin: 0}}>
                            {finding.references.map((ref, i) => <li key={i}><a href={ref} target="_blank" rel="noopener noreferrer">{ref}</a></li>)}
                        </ul>
                    </Descriptions.Item>
                )}
            </Descriptions>

            {finding.fixes?.code && finding.fixes?.original_snippet && (
              <EnhancedDiffViewer
                title="AI-Suggested Fix"
                oldCode={finding.fixes.original_snippet}
                newCode={finding.fixes.code}
                oldCodeTitle="Original Code"
                newCodeTitle="Suggested Fix"
              />
            )}
        </Panel>
      ))}
    </Collapse>
  );
};

export default FindingList;