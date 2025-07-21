import { BulbOutlined } from '@ant-design/icons';
import { Alert, Card, Space, Typography } from 'antd';
import React from 'react';
import type { Finding } from '../../../shared/types/api';

const { Title } = Typography;

interface FileMergeExplanationsProps {
  findings: Finding[];
}

const FileMergeExplanations: React.FC<FileMergeExplanationsProps> = ({ findings }) => {
  // A merged fix is identified by its description matching the fix's description,
  // and it must have been the one applied in the final remediation.
  const mergedFindings = findings.filter(
    (f) => f.fixes?.description && f.description === f.fixes.description && f.is_applied_in_remediation
  );

  if (mergedFindings.length === 0) {
    return null;
  }

  return (
    <Card
      style={{ marginTop: 24, marginBottom: 16 }}
      title={
        <Space>
          <BulbOutlined />
          <Title level={5} style={{ margin: 0 }}>
            AI Remediation Summary
          </Title>
        </Space>
      }
    >
      {mergedFindings.map((finding) => (
        <Alert
          key={finding.id}
          message={`Explanation for Fix near Line ${finding.line_number}`}
          description={<pre style={{ whiteSpace: 'pre-wrap', fontFamily: 'inherit', margin: 0 }}>{finding.description}</pre>}
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
        />
      ))}
    </Card>
  );
};

export default FileMergeExplanations;