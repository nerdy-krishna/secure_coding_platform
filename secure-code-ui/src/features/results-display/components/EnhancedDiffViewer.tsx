import { CopyOutlined, DownOutlined, UpOutlined } from '@ant-design/icons';
import { DiffEditor } from "@monaco-editor/react";
import { Button, Card, Divider, Space, Tooltip, Typography, message } from 'antd';
import React, { useState } from 'react';
import './EnhancedDiffViewer.css';

const { Text } = Typography;

interface EnhancedDiffViewerProps {
  oldCode: string;
  newCode: string;
  title: string;
  filePath?: string;
}

const getLanguageFromPath = (filePath?: string): string => {
    if (!filePath) return 'plaintext';
    const extension = filePath.split('.').pop()?.toLowerCase();
    switch (extension) {
        case 'js': return 'javascript';
        case 'ts': return 'typescript';
        case 'py': return 'python';
        case 'java': return 'java';
        case 'html': return 'html';
        case 'css': return 'css';
        case 'json': return 'json';
        case 'php': return 'php';
        case 'sql': return 'sql';
        default: return 'plaintext';
    }
};


const EnhancedDiffViewer: React.FC<EnhancedDiffViewerProps> = ({
  oldCode,
  newCode,
  title,
  filePath,
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

    const language = getLanguageFromPath(filePath);

    return (
        <>
            <Divider />
            <Card
                className="enhanced-diff-viewer-card"
                title={cardTitle}
                size="small"
                extra={cardExtra}
                headStyle={{ padding: '0 16px' }}
                bodyStyle={{ padding: isExpanded ? '16px 16px 8px 16px' : '0' }}
            >
                {isExpanded && (
                    <DiffEditor
                        height="40vh"
                        language={language}
                        original={oldCode}
                        modified={newCode}
                        theme="light"
                        options={{
                            readOnly: true,
                            renderSideBySide: true,
                            minimap: { enabled: false }
                        }}
                    />
                )}
            </Card>
        </>
    );
};

export default EnhancedDiffViewer;