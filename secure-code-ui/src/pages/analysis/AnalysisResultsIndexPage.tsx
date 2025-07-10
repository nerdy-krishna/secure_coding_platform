import {
    HistoryOutlined,
    ProjectOutlined,
} from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import {
    Alert,
    Button,
    Card,
    Empty,
    Input,
    List,
    Spin,
    Typography,
} from 'antd';
import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { scanService } from '../../shared/api/scanService';
import type { PaginatedProjectHistoryResponse, ProjectHistoryItem } from '../../shared/types/api';

const { Title, Paragraph } = Typography;
const { Search } = Input;

const AnalysisResultsIndexPage: React.FC = () => {
    const [searchTerm, setSearchTerm] = useState('');
    const [debouncedSearchTerm, setDebouncedSearchTerm] = useState('');

    useEffect(() => {
        const timer = setTimeout(() => {
            setDebouncedSearchTerm(searchTerm);
        }, 500);
        return () => clearTimeout(timer);
    }, [searchTerm]);

    const { data, isLoading, isError, error, isFetching } = useQuery<PaginatedProjectHistoryResponse, Error>({
        queryKey: ["projectHistory", debouncedSearchTerm],
        queryFn: () => scanService.getProjectHistory(1, 100, debouncedSearchTerm),
    });

    if (isLoading) {
      return <Spin tip="Loading projects..." size="large" style={{ display: 'block', marginTop: '50px' }} />;
    }
  
    if (isError) {
      return <Alert message="Error" description={`Could not fetch projects: ${error.message}`} type="error" showIcon />;
    }
    
    return (
        <Card>
            <Title level={2} style={{ display: 'flex', alignItems: 'center' }}>
                <ProjectOutlined style={{ marginRight: 16 }} />
                Projects Overview
            </Title>
            <Paragraph type="secondary">
               Browse all your projects. Select a project to view its detailed scan history and reports.
            </Paragraph>
            <Search
                placeholder="Search by Project Name..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                onSearch={(value) => setDebouncedSearchTerm(value)}
                style={{ marginBottom: 24 }}
                enterButton
                loading={isFetching}
                allowClear
            />
            
            {!data || data.items.length === 0 ? (
                 <Empty description={
                    <>
                        <Title level={4}>No Projects Found</Title>
                        <Paragraph>Get started by submitting code for your first project.</Paragraph>
                        <Link to="/submission/submit">
                            <Button type="primary">Start Your First Scan</Button>
                        </Link>
                    </>
                } />
            ) : (
                <List
                    grid={{ gutter: 16, xs: 1, sm: 1, md: 2, lg: 3, xl: 3, xxl: 4 }}
                    dataSource={data.items}
                    renderItem={(project: ProjectHistoryItem) => (
                        <List.Item>
                            <Card
                                title={project.name}
                                actions={[
                                    <Link to={`/account/history#${project.id}`}>
                                        <Button type="primary" icon={<HistoryOutlined />}>View History</Button>
                                    </Link>
                                ]}
                            >
                                <Paragraph type="secondary" ellipsis={{rows: 2}}>
                                    {project.repository_url ? (
                                        <a href={project.repository_url} target="_blank" rel="noopener noreferrer">{project.repository_url}</a>
                                    ) : (
                                        "Manually uploaded project."
                                    )}
                                </Paragraph>
                            </Card>
                        </List.Item>
                    )}
                />
            )}
        </Card>
    );
};

export default AnalysisResultsIndexPage;