import {
    CodeOutlined,
    DeleteOutlined,
    FileSearchOutlined,
    ProjectOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { TableProps } from 'antd';
import {
    Alert,
    Button,
    Card,
    Col,
    Empty,
    Input,
    Popconfirm,
    Row,
    Space,
    Spin,
    Table,
    Tag,
    Typography,
    message,
} from 'antd';
import { saveAs } from 'file-saver';
import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { scanService } from '../../shared/api/scanService';
import { useAuth } from '../../shared/hooks/useAuth';
import { useDebounce } from '../../shared/hooks/useDebounce';
import type { PaginatedProjectHistoryResponse, ProjectHistoryItem, ScanHistoryItem } from '../../shared/types/api';

const { Title, Paragraph } = Typography;
const { Search } = Input;

const getStatusTag = (status: string) => {
    if (status.includes('COMPLETED')) return <Tag color="green">Completed</Tag>;
    if (status.includes('FAILED') || status.includes('CANCELLED')) return <Tag color="red">Failed</Tag>;
    if (status.includes('PENDING')) return <Tag color="gold">Pending Approval</Tag>;
    return <Tag color="blue">In Progress</Tag>;
};

const AnalysisResultsIndexPage: React.FC = () => {
    const { user } = useAuth();
    const queryClient = useQueryClient();
    const [searchTerm, setSearchTerm] = useState('');
    const debouncedSearchTerm = useDebounce(searchTerm, 500);

    const { data, isLoading, isError, error, isFetching } = useQuery<PaginatedProjectHistoryResponse, Error>({
        queryKey: ["projectHistory", debouncedSearchTerm],
        queryFn: () => scanService.getProjectHistory(1, 100, debouncedSearchTerm),
    });

    const deleteProjectMutation = useMutation({
        mutationFn: (projectId: string) => scanService.deleteProject(projectId),
        onSuccess: () => {
            message.success("Project deleted successfully.");
            queryClient.invalidateQueries({ queryKey: ["projectHistory"] });
        },
        onError: (error: Error) => message.error(`Failed to delete project: ${error.message}`),
    });

    const handleDownloadSarif = async (scanId: string) => {
        try {
            const sarifReport = await scanService.downloadSarifReport(scanId);
            const sarifString = JSON.stringify(sarifReport, null, 2);
            const blob = new Blob([sarifString], { type: "application/sarif+json;charset=utf-8" });
            saveAs(blob, `scan-report-${scanId}.sarif`);
        } catch (error) {
            message.error("Failed to download SARIF report.");
            console.error(error);
        }
    };

    const expandedRowRender = (project: ProjectHistoryItem) => {
        const columns: TableProps<ScanHistoryItem>['columns'] = [
            { title: 'Scan ID', dataIndex: 'id', key: 'id', render: (id) => <Typography.Text copyable={{text: id}}>{id.substring(0,8)}...</Typography.Text> },
            { title: 'Type', dataIndex: 'scan_type', key: 'scan_type' },
            { title: 'Status', dataIndex: 'status', key: 'status', render: getStatusTag },
            { title: 'Submitted', dataIndex: 'created_at', key: 'created_at', render: (date) => new Date(date).toLocaleString() },
            {
              title: 'Actions',
              key: 'actions',
              render: (_, scan) => (
                <Space size="small" wrap>
                  <Link to={`/analysis/results/${scan.id}`}><Button type="primary" size="small">View Report</Button></Link>
                  {scan.has_impact_report && <Link to={`/scans/${scan.id}/executive-summary`}><Button size="small">Summary</Button></Link>}
                  {scan.has_sarif_report && <Button size="small" icon={<CodeOutlined />} onClick={() => handleDownloadSarif(scan.id)}>SARIF</Button>}
                  <Link to={`/scans/${scan.id}/llm-logs`}><Button size="small" icon={<FileSearchOutlined />}>Logs</Button></Link>
                </Space>
              ),
            },
        ];

        return <Table columns={columns} dataSource={project.scans} pagination={false} rowKey="id" size="small" />;
    };

    const mainColumns: TableProps<ProjectHistoryItem>['columns'] = [
        {
            title: 'Project Name',
            dataIndex: 'name',
            key: 'name',
            sorter: (a, b) => a.name.localeCompare(b.name),
        },
        {
            title: 'Repository URL',
            dataIndex: 'repository_url',
            key: 'repository_url',
            render: (url) => url ? <a href={url} target="_blank" rel="noopener noreferrer">{url}</a> : <Typography.Text type="secondary">N/A</Typography.Text>,
            ellipsis: true,
        },
        {
            title: 'Total Scans',
            dataIndex: 'scans',
            key: 'total_scans',
            render: (scans) => scans.length,
            align: 'right',
        },
        {
            title: 'Last Scanned',
            dataIndex: 'updated_at',
            key: 'last_scanned',
            render: (date) => new Date(date).toLocaleString(),
            sorter: (a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime(),
        },
        {
          title: 'Actions',
          key: 'actions',
          render: (_, project) => (
            <Space>
              <Link to="/submission/submit" state={{ projectName: project.name }}>
                <Button size="small">New Scan</Button>
              </Link>
              {user?.is_superuser && (
                  <Popconfirm
                      title={`Delete project "${project.name}"?`}
                      description="This will delete the project and ALL its scans. This action cannot be undone."
                      onConfirm={() => deleteProjectMutation.mutate(project.id)}
                      okText="Yes" cancelText="No"
                  >
                      <Button danger size="small" icon={<DeleteOutlined />} loading={deleteProjectMutation.isPending && deleteProjectMutation.variables === project.id} />
                  </Popconfirm>
              )}
            </Space>
          ),
        },
    ];

    if (isLoading) {
      return <Spin tip="Loading projects..." size="large" style={{ display: 'block', marginTop: '50px' }} />;
    }
  
    if (isError) {
      return <Alert message="Error" description={`Could not fetch projects: ${error.message}`} type="error" showIcon />;
    }
    
    return (
        <Card>
            <Row justify="space-between" align="middle" style={{marginBottom: 24}}>
                <Col>
                    <Title level={2} style={{ margin: 0, display: 'flex', alignItems: 'center' }}>
                        <ProjectOutlined style={{ marginRight: 16 }} />
                        Projects
                    </Title>
                    <Paragraph type="secondary">
                      Browse all projects and expand to see their scan histories.
                    </Paragraph>
                </Col>
                <Col>
                    <Link to="/submission/submit">
                        <Button type="primary">Start New Scan</Button>
                    </Link>
                </Col>
            </Row>

            <Search
                placeholder="Search by Project Name..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{ marginBottom: 24 }}
                loading={isFetching}
                allowClear
            />
            
            <Table
                columns={mainColumns}
                expandable={{ expandedRowRender, defaultExpandAllRows: false }}
                dataSource={data?.items}
                rowKey="id"
                loading={isLoading}
                locale={{ emptyText: 
                     <Empty description="No projects found.">
                        <Link to="/submission/submit">
                            <Button type="primary">Start Your First Scan</Button>
                        </Link>
                    </Empty>
                }}
            />
        </Card>
    );
};

export default AnalysisResultsIndexPage;