import { CopyOutlined, DownOutlined, UpOutlined } from '@ant-design/icons';
import { Button, Card, Divider, Space, Tooltip, Typography, message } from 'antd';
import React, { useState } from 'react';
import ReactDiffViewer, { DiffMethod } from 'react-diff-viewer-continued';
import './EnhancedDiffViewer.css';

const { Text } = Typography;

interface EnhancedDiffViewerProps {
  oldCode: string;
  newCode: string;
  oldCodeTitle?: string;
  newCodeTitle?: string;
  title: string;
}

const EnhancedDiffViewer: React.FC<EnhancedDiffViewerProps> = ({
  oldCode,
  newCode,
  oldCodeTitle = 'Original',
  newCodeTitle = 'Changed',
  title,
}) => {
    const [isExpanded, setIsExpanded] = useState(true);

  const handleCopyNew = () => {
    navigator.clipboard.writeText(newCode);
    message.success("Copied new code to clipboard!");
  };

  const handleCopyOld = () => {
    navigator.clipboard.writeText(oldCode);
    message.success("Copied original code to clipboard!");
  };

  const toggleExpand = () => setIsExpanded(!isExpanded);

  const cardTitle = (
    <Space>
      <Text strong>{title}</Text>
    </Space>
  );

  const cardExtra = (
    <Space>
      <Tooltip title="Copy the original code snippet">
        <Button icon={<CopyOutlined />} onClick={handleCopyOld} size="small">
          Copy Original
        </Button>
      </Tooltip>
      <Tooltip title="Copy the new code snippet">
        <Button icon={<CopyOutlined />} onClick={handleCopyNew} size="small" type="primary">
          Copy Fix
        </Button>
      </Tooltip>
      <Tooltip title={isExpanded ? "Collapse" : "Expand"}>
        <Button
          icon={isExpanded ? <UpOutlined /> : <DownOutlined />}
          onClick={toggleExpand}
          size="small"
        />
      </Tooltip>
    </Space>
  );

  return (
    <>
      <Divider />
      <Card
        className="enhanced-diff-viewer-card"
        title={cardTitle}
        size="small"
        extra={cardExtra}
        headStyle={{ padding: '0 16px' }}
        bodyStyle={{ padding: 0 }}
      >
        {isExpanded && (
          <ReactDiffViewer
            oldValue={oldCode}
            newValue={newCode}
            splitView={true}
            hideLineNumbers={false}
            useDarkTheme={false}
            leftTitle={oldCodeTitle}
            rightTitle={newCodeTitle}
            compareMethod={DiffMethod.WORDS}
          />
        )}
      </Card>
    </>
  );
};

export default EnhancedDiffViewer;