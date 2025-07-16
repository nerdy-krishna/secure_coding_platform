import { HistoryOutlined } from "@ant-design/icons";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import {
    Alert,
    Button,
    Card,
    Col,
    Empty,
    Input,
    Pagination,
    Row,
    Select,
    Space,
    Spin,
    Typography
} from "antd";
import React, { useState } from "react";
import { Link } from "react-router-dom";
import ScanCard from "../../features/submission-history/components/ScanCard";
import { scanService } from "../../shared/api/scanService";
import { useDebounce } from "../../shared/hooks/useDebounce";
import { useNotifications } from "../../shared/hooks/useNotifications";
import type { ScanHistoryItem } from "../../shared/types/api";

const { Title, Paragraph } = Typography;
const { Option } = Select;

const STATUS_GROUPS = [
    'All', 'Completed', 'In Progress', 'Failed', 'Pending Approval'
];

const SubmissionHistoryPage: React.FC = () => {
    const [pagination, setPagination] = useState({ page: 1, pageSize: 5 });
    const [searchTerm, setSearchTerm] = useState("");
    const [sortOrder, setSortOrder] = useState("desc");
    const [statusFilter, setStatusFilter] = useState("All");

    const debouncedSearchTerm = useDebounce(searchTerm, 500);
    const { permission, requestPermission } = useNotifications();

    const { data, isLoading, isError, error, isFetching } = useQuery({
        queryKey: ["scanHistory", pagination.page, pagination.pageSize, debouncedSearchTerm, sortOrder, statusFilter],
        queryFn: () => scanService.getScanHistory(pagination.page, pagination.pageSize, debouncedSearchTerm, sortOrder, statusFilter),
        placeholderData: keepPreviousData,
        refetchInterval: 10000, // Refetch every 10 seconds
    });
    
    if (isError) {
        return <Alert message="Error" description={`Could not fetch scan history: ${error.message}`} type="error" showIcon />;
    }

    return (
        <Space direction="vertical" style={{ width: "100%" }} size="large">
            <Row justify="space-between" align="middle">
                <Col>
                    <Title level={2}><HistoryOutlined /> Submission History</Title>
                    <Paragraph type="secondary">Review the status and results of all your individual scans.</Paragraph>
                </Col>
                <Col>
                    {permission === 'default' && (
                        <Button onClick={requestPermission}>Enable Notifications</Button>
                    )}
                </Col>
            </Row>

             <Card>
                <Row gutter={[16, 16]} align="bottom">
                    <Col xs={24} md={10}>
                        <Paragraph style={{marginBottom: 4, fontWeight: 500}}>Search by Project, ID, or Status</Paragraph>
                        <Input.Search
                            placeholder="Search scans..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            loading={isFetching}
                            enterButton
                        />
                    </Col>
                    <Col xs={12} md={7}>
                        <Paragraph style={{marginBottom: 4, fontWeight: 500}}>Filter by Status</Paragraph>
                        <Select value={statusFilter} onChange={setStatusFilter} style={{ width: '100%' }}>
                           {STATUS_GROUPS.map(group => <Option key={group} value={group}>{group}</Option>)}
                        </Select>
                    </Col>
                    <Col xs={12} md={7}>
                        <Paragraph style={{marginBottom: 4, fontWeight: 500}}>Sort by Date</Paragraph>
                        <Select value={sortOrder} onChange={setSortOrder} style={{ width: '100%' }}>
                            <Option value="desc">Newest First</Option>
                            <Option value="asc">Oldest First</Option>
                        </Select>
                    </Col>
                </Row>
            </Card>
            
            {isLoading && <div style={{textAlign: 'center', padding: '50px'}}><Spin tip="Loading scans..." size="large" /></div>}

            {!isLoading && data?.items.length === 0 && (
                 <Card>
                    <Empty description={
                        <>
                            <Title level={4}>No Scans Found</Title>
                            <Paragraph>Get started by submitting code for your first project.</Paragraph>
                            <Link to="/submission/submit">
                                <Button type="primary">Start Your First Scan</Button>
                            </Link>
                        </>
                    } />
                </Card>
            )}

            {!isLoading && data && data.items.length > 0 && (
                <>
                    {data.items.map((scan: ScanHistoryItem) => (
                        <ScanCard key={scan.id} scan={scan} />
                    ))}
                    <Pagination
                        style={{textAlign: 'center', marginTop: 16}}
                        current={pagination.page}
                        pageSize={pagination.pageSize}
                        total={data?.total || 0}
                        onChange={(page, pageSize) => setPagination({ page, pageSize })}
                        showSizeChanger
                        pageSizeOptions={['5', '10', '20', '50']}
                    />
                </>
            )}
        </Space>
    );
};

export default SubmissionHistoryPage;