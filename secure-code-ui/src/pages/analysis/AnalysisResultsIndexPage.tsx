// secure-code-ui/src/pages/analysis/AnalysisResultsIndexPage.tsx
import { FileTextOutlined, ProfileOutlined } from '@ant-design/icons';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import type { TableProps } from 'antd';
import { Card, Input, Table, Tag, Tooltip, Typography } from 'antd';
import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { submissionService } from '../../shared/api/submissionService';
import type { PaginatedResultsResponse, ResultIndexItem } from '../../shared/types/api';

const { Title, Paragraph, Text } = Typography;
const { Search } = Input;

// Helper function to determine risk score color
const getRiskScoreColor = (score: number) => {
    if (score > 50) return 'volcano';
    if (score > 20) return 'orange';
    if (score > 0) return 'gold';
    return 'green';
};

const AnalysisResultsIndexPage: React.FC = () => {
    const [pagination, setPagination] = useState({ page: 1, pageSize: 10 });
    const [searchTerm, setSearchTerm] = useState('');
    const [debouncedSearchTerm, setDebouncedSearchTerm] = useState('');

    useEffect(() => {
        const timer = setTimeout(() => {
            setDebouncedSearchTerm(searchTerm);
            setPagination(p => ({ ...p, page: 1 }));
        }, 500);
        return () => clearTimeout(timer);
    }, [searchTerm]);

    const { data, isLoading, isError, isFetching } = useQuery<PaginatedResultsResponse, Error>({
        queryKey: ["analysisResults", pagination.page, pagination.pageSize, debouncedSearchTerm],
        queryFn: () => submissionService.getResults(pagination.page, pagination.pageSize, debouncedSearchTerm),
        placeholderData: keepPreviousData,
    });

    const columns: TableProps<ResultIndexItem>['columns'] = [
        {
            title: 'Project Name',
            dataIndex: 'project_name',
            key: 'project_name',
            render: (text, record) => <Link to={`/analysis/results/${record.submission_id}`}>{text}</Link>,
        },
        {
            title: 'Submission ID',
            dataIndex: 'submission_id',
            key: 'submission_id',
            render: (id) => <Text copyable style={{fontFamily: 'monospace'}}>{id}</Text>
        },
        {
            title: 'Completion Date',
            dataIndex: 'completed_at',
            key: 'completed_at',
            render: (text) => text ? new Date(text).toLocaleString() : 'N/A',
            sorter: (a, b) => new Date(a.completed_at || 0).getTime() - new Date(b.completed_at || 0).getTime(),
            defaultSortOrder: 'descend',
        },
        {
            title: 'Risk Score',
            dataIndex: 'risk_score',
            key: 'risk_score',
            sorter: (a, b) => a.risk_score - b.risk_score,
            render: (score) => <Tag color={getRiskScoreColor(score)} style={{fontSize: 14, padding: '4px 8px'}}>{score}</Tag>,
            align: 'center',
        },
        {
            title: 'Total Findings',
            dataIndex: 'total_findings',
            key: 'total_findings',
            sorter: (a, b) => a.total_findings - b.total_findings,
            align: 'center',
            render: (count) => <Tag icon={<FileTextOutlined/>} color="blue">{count}</Tag>
        },
        {
            title: 'Severity Breakdown',
            key: 'severity',
            render: (_, record) => (
                <Tooltip title={`Critical: ${record.critical_findings}, High: ${record.high_findings}, Medium: ${record.medium_findings}, Low: ${record.low_findings}`}>
                    <Tag color="red">{record.critical_findings}</Tag>
                    <Tag color="orange">{record.high_findings}</Tag>
                    <Tag color="gold">{record.medium_findings}</Tag>
                    <Tag color="geekblue">{record.low_findings}</Tag>
                </Tooltip>
            ),
        }
    ];

    return (
        <Card>
            <Title level={2} style={{ display: 'flex', alignItems: 'center' }}>
                <ProfileOutlined style={{ marginRight: 16 }} />
                Analysis Results
            </Title>
            <Paragraph type="secondary">
                Browse, search, and filter all completed analysis reports.
            </Paragraph>
            <Search
                placeholder="Search by Project Name or Submission ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                onSearch={(value) => setDebouncedSearchTerm(value)}
                style={{ marginBottom: 24 }}
                enterButton
                loading={isFetching}
                allowClear
            />
            <Table
                columns={columns}
                rowKey="submission_id"
                dataSource={data?.items}
                loading={isLoading}
                pagination={{
                    current: pagination.page,
                    pageSize: pagination.pageSize,
                    total: data?.total || 0,
                    showSizeChanger: true,
                    pageSizeOptions: ['10', '20', '50'],
                }}
                onChange={(paginationConfig) => {
                    setPagination({
                        page: paginationConfig.current ?? 1,
                        pageSize: paginationConfig.pageSize ?? 10,
                    });
                }}
            />
            {isError && <Paragraph type="danger">Failed to load analysis results.</Paragraph>}
        </Card>
    );
};

export default AnalysisResultsIndexPage;