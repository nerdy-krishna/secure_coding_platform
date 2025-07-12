// src/features/results-display/components/SnippetDiffViewer.tsx
import { Card, Empty } from 'antd';
import React from 'react';
import ReactDiffViewer from 'react-diff-viewer-continued';
import type { Finding } from '../../../shared/types/api';

interface SnippetDiffViewerProps {
    finding: Finding | null;
}

const SnippetDiffViewer: React.FC<SnippetDiffViewerProps> = ({ finding }) => {
    const suggestedFix = finding?.fixes?.[0];

    if (!finding || !suggestedFix) {
        return (
            <Card title="Code Fix Snippet" style={{ marginTop: 16 }}>
                <Empty description="Select a finding to see the suggested code fix." />
            </Card>
        );
    }
    
    return (
        <Card title={`Suggested Fix for: ${finding.title}`} style={{ marginTop: 16 }}>
            <ReactDiffViewer
                oldValue={suggestedFix.original_snippet || ''}
                newValue={suggestedFix.suggested_fix || ''}
                splitView={false}
                hideLineNumbers={true}
                useDarkTheme={false}
            />
        </Card>
    );
};

export default SnippetDiffViewer;