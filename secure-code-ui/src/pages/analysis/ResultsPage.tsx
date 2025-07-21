import {
  ArrowLeftOutlined,
  CodeOutlined,
  FilePdfOutlined,
  LoadingOutlined,
  MinusSquareOutlined,
  PlusSquareOutlined,
} from "@ant-design/icons";
import { useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Card,
  Col,
  Divider,
  Empty,
  Input,
  Layout,
  Row,
  Select,
  Space,
  Spin,
  Tag,
  Typography
} from "antd";
import { saveAs } from "file-saver";
import React, { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import EnhancedDiffViewer from "../../features/results-display/components/EnhancedDiffViewer";
import FileMergeExplanations from "../../features/results-display/components/FileMergeExplanations";
import FindingList from "../../features/results-display/components/FindingList";
import ResultsFileTree from "../../features/results-display/components/ResultsFileTree";
import ScanSummary from "../../features/results-display/components/ScanSummary";
import { scanService } from "../../shared/api/scanService";
import type { Finding, ScanResultResponse } from "../../shared/types/api";

const { Content, Sider } = Layout;
const { Title, Paragraph } = Typography;
const { Option } = Select;
type GroupableFields = keyof Pick<Finding, 'severity' | 'confidence' | 'cwe' | 'corroborating_agents' | 'title'>;
type FilterableFields = keyof Pick<Finding, 'severity' | 'confidence' | 'corroborating_agents' | 'title'>;

const ResultsPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
  const [activeFindingKeys, setActiveFindingKeys] = useState<string[]>([]);
  const [sortConfig, setSortConfig] = useState<{ field: keyof Finding; order: 'asc' | 'desc' }>({ field: 'severity', order: 'desc' });
  const [filters, setFilters] = useState<Partial<Record<FilterableFields, string[]>>>({});
  const [groupBy, setGroupBy] = useState<GroupableFields | 'none'>('severity');
  const [idFilter, setIdFilter] = useState<string>('');

  const { data: result, isLoading, isError, error } = useQuery<ScanResultResponse, Error>({
    queryKey: ["scanResult", scanId],
    queryFn: () => {
      if (!scanId) throw new Error("Scan ID is missing");
      return scanService.getScanResult(scanId);
    },
    enabled: !!scanId,
    refetchOnWindowFocus: false,
  });

  const allFindingsForScan = useMemo(() => {
    return result?.summary_report?.files_analyzed?.flatMap(file => file.findings) || [];
  }, [result]);

  const allFindingsInFile = useMemo(() => {
    if (!selectedFilePath) return [];
    return result?.summary_report?.files_analyzed?.find(f => f.file_path === selectedFilePath)?.findings || [];
  }, [result, selectedFilePath]);

  const dynamicFilterOptions = useMemo(() => {
    const options: Record<string, string[]> = { severity: [], confidence: [], corroborating_agents: [], title: [] };
    const activeFilters = Object.entries(filters).filter(([, values]) => values && values.length > 0);

    for (const key in options) {
      const otherFilters = activeFilters.filter(([filterKey]) => filterKey !== key);
      const relevantFindings = allFindingsInFile.filter(finding => {
        return otherFilters.every(([filterKey, values]) => {
          const findingValue = finding[filterKey as FilterableFields];
          if (filterKey === 'corroborating_agents' && Array.isArray(findingValue)) {
            return findingValue.some(agent => values.includes(agent));
          }
          return findingValue ? values.includes(String(findingValue)) : false;
        });
      });
      if (key === 'corroborating_agents') {
        options[key] = [...new Set(relevantFindings.flatMap(f => f.corroborating_agents || []))];
      } else {
        options[key as FilterableFields] = [...new Set(relevantFindings.map(f => f[key as FilterableFields]).filter(Boolean))] as string[];
      }
    }
    return options;
  }, [allFindingsInFile, filters]);

  const filteredAndSortedFindings = useMemo(() => {
    let findings = [...allFindingsInFile];

    // Apply ID filter first if it exists
    if (idFilter.trim()) {
      findings = findings.filter(finding => String(finding.id).includes(idFilter.trim()));
    }

    // Then, apply the multi-select filters
    findings = findings.filter(finding => {
      return Object.entries(filters).every(([key, values]) => {
        if (!values || values.length === 0) return true;
        const keyTyped = key as FilterableFields;

        if (keyTyped === 'corroborating_agents') {
            return (finding.corroborating_agents || []).some(agent => values.includes(agent));
        }
        
        const findingValue = finding[keyTyped];
        return findingValue ? values.includes(String(findingValue)) : false;
      });
    });

    const severityOrder: Record<string, number> = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFORMATIONAL': 1 };
    findings.sort((a, b) => {
      const field = sortConfig.field;
      let valA = a[field];
      let valB = b[field];

      if (field === 'severity') {
        valA = severityOrder[a.severity.toUpperCase()] || 0;
        valB = severityOrder[b.severity.toUpperCase()] || 0;
      }

      if (valA === undefined || valA === null) return 1;
      if (valB === undefined || valB === null) return -1;
      
      let comparison = 0;
      if (typeof valA === 'string' && typeof valB === 'string') {
        comparison = valA.localeCompare(valB);
      } else if (typeof valA === 'number' && typeof valB === 'number') {
        comparison = valA - valB;
      }
      
      return sortConfig.order === 'asc' ? comparison : -comparison;
    });

    return findings;
  }, [allFindingsInFile, sortConfig, filters, idFilter]);

  const groupedFindings = useMemo(() => {
    if (groupBy === 'none') {
      return { 'all': filteredAndSortedFindings };
    }
    return filteredAndSortedFindings.reduce((acc, finding) => {
      if (groupBy === 'corroborating_agents') {
          const agents = finding.corroborating_agents && finding.corroborating_agents.length > 0 ? finding.corroborating_agents : ['Unknown'];
          agents.forEach(agent => {
              if (!acc[agent]) acc[agent] = [];
              acc[agent].push(finding);
          });
      } else {
          const key = String(finding[groupBy as keyof Finding] ?? 'Unknown');
          if (!acc[key]) {
            acc[key] = [];
          }
          acc[key].push(finding);
      }
      return acc;
    }, {} as Record<string, Finding[]>);
  }, [filteredAndSortedFindings, groupBy]);

  useEffect(() => {
    const filesWithFindings = result?.summary_report?.files_analyzed?.filter(f => f.findings.length > 0) || [];
    if (!selectedFilePath && filesWithFindings.length > 0) {
        setSelectedFilePath(filesWithFindings[0].file_path);
    }
  }, [result, selectedFilePath]);

  const handleFilterChange = (key: FilterableFields, values: string[]) => {
    setFilters(prev => ({...prev, [key]: values}));
  };

  const handleDownloadSarif = () => {
    if (result?.sarif_report) {
      const sarifString = JSON.stringify(result.sarif_report, null, 2);
      const blob = new Blob([sarifString], { type: "application/sarif+json;charset=utf-8" });
      saveAs(blob, `scan-report-${scanId}.sarif`);
    }
  };

  if (isLoading) return <Spin indicator={<LoadingOutlined style={{ fontSize: 48 }} spin />} tip="Loading Report..." style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh" }} />;
  if (isError) return <Alert message="Error" description={error.message} type="error" showIcon />;
  if (!result || !result.summary_report) return <Empty description="No analysis results found for this scan." />;

  const { summary_report, status, original_code_map, fixed_code_map } = result;
  const isRemediationComplete = status === 'REMEDIATION_COMPLETED';

  const originalCode = original_code_map?.[selectedFilePath || ""] || "";
  const fixedCode = fixed_code_map?.[selectedFilePath || ""] || "";
  
  return (
    <Layout style={{ background: 'transparent' }}>
      <Row justify="space-between" align="middle" style={{ marginBottom: 16 }}>
        <Col>
            <Title level={3} style={{ margin: 0 }}>{summary_report.scan_type.replace(/_/g, ' ')} Report: {summary_report.project_name}</Title>
            <Paragraph copyable={{ text: scanId }} type="secondary" style={{margin: 0}}>Scan ID: {scanId}</Paragraph>
            <Paragraph copyable={{ text: summary_report.project_id }} type="secondary" style={{margin: 0}}>Project ID: {summary_report.project_id}</Paragraph>
        </Col>
        <Col>
            <Space>
                {result?.impact_report && <Link to={`/scans/${scanId}/executive-summary`}><Button icon={<FilePdfOutlined />}>Executive Summary</Button></Link>}
                {result?.sarif_report && <Button icon={<CodeOutlined />} onClick={handleDownloadSarif}>Download SARIF</Button>}
                <Button onClick={() => navigate("/account/history")} icon={<ArrowLeftOutlined />}>Back to History</Button>
            </Space>
        </Col>
      </Row>
      
      <ScanSummary summaryReport={summary_report} />

      <Card size="small" style={{ marginBottom: 16 }}>
        <Row gutter={[16, 8]} align="bottom">
          <Col xs={24} sm={12} md={6}>
            <Typography.Text>Group By:</Typography.Text>
            <Select value={groupBy} onChange={(value) => setGroupBy(value as GroupableFields | 'none')} style={{ width: '100%' }}>
                <Option value="none">None</Option>
                <Option value="severity">Severity</Option>
                <Option value="confidence">Confidence</Option>
                <Option value="corroborating_agents">Agent</Option>
                <Option value="title">Finding Title</Option>
            </Select>
          </Col>
          <Col xs={24} sm={12} md={6}>
              <Typography.Text>Sort By:</Typography.Text>
              <Select value={sortConfig.field} onChange={(field) => setSortConfig(prev => ({ ...prev, field }))} style={{ width: '100%' }}>
                  <Option value="severity">Severity</Option>
                  <Option value="confidence">Confidence</Option>
                  <Option value="line_number">Line Number</Option>
                  <Option value="title">Finding Title</Option>
              </Select>
          </Col>
          <Col xs={12} sm={12} md={6}>
            <Typography.Text>Order:</Typography.Text>
            <Select value={sortConfig.order} onChange={(order) => setSortConfig(prev => ({ ...prev, order }))} style={{ width: '100%' }}>
                <Option value="desc">Descending</Option>
                <Option value="asc">Ascending</Option>
            </Select>
          </Col>
          <Col xs={12} sm={12} md={6}>
            <Typography.Text>Filter by Severity:</Typography.Text>
            <Select mode="multiple" allowClear style={{ width: '100%' }} placeholder="All Severities" onChange={(values) => handleFilterChange('severity', values)} value={filters.severity}>
                {dynamicFilterOptions.severity.map(s => <Option key={s} value={s}>{s}</Option>)}
            </Select>
          </Col>
          <Col xs={12} sm={12} md={6}>
            <Typography.Text>Filter by Confidence:</Typography.Text>
            <Select mode="multiple" allowClear style={{ width: '100%' }} placeholder="All Confidences" onChange={(values) => handleFilterChange('confidence', values)} value={filters.confidence}>
                {dynamicFilterOptions.confidence.map(s => <Option key={s} value={s}>{s}</Option>)}
            </Select>
          </Col>
          <Col xs={12} sm={12} md={6}>
            <Typography.Text>Filter by Finding ID:</Typography.Text>
            <Input.Search
                placeholder="Enter ID"
                value={idFilter}
                onChange={(e) => setIdFilter(e.target.value)}
                allowClear
            />
          </Col>
          <Col xs={12} sm={12} md={6}>
            <Typography.Text>Filter by Agent:</Typography.Text>
            <Select mode="multiple" allowClear style={{ width: '100%' }} placeholder="All Agents" onChange={(values) => handleFilterChange('corroborating_agents', values)} value={filters.corroborating_agents}>
                {dynamicFilterOptions.corroborating_agents.map(s => <Option key={s} value={s}>{s}</Option>)}
            </Select>
          </Col>
          <Col xs={24} sm={24} md={12}>
            <Typography.Text>Filter by Finding Title:</Typography.Text>
            <Select mode="multiple" allowClear style={{ width: '100%' }} placeholder="All Titles" onChange={(values) => handleFilterChange('title', values)} value={filters.title}>
                {dynamicFilterOptions.title.map(s => <Option key={s} value={s}>{s}</Option>)}
            </Select>
          </Col>
        </Row>
      </Card>
      
      <Layout style={{ background: '#fff', borderRadius: 8, border: '1px solid #f0f0f0', flexDirection: 'column' }}>
        <Layout>
          <Sider width={350} style={{ background: "#fafafa", padding: "16px", overflow: "auto", borderRight: '1px solid #f0f0f0', borderRadius: '8px 0 0 8px' }}>
              <Title level={5} style={{ marginTop: 0, marginBottom: 16 }}>Analyzed Files</Title>
              <ResultsFileTree
                analyzedFiles={summary_report.files_analyzed || []}
                findings={allFindingsForScan}
                selectedKeys={selectedFilePath ? [selectedFilePath] : []}
                onSelect={(keys) => {
                    if (keys.length > 0) {
                      setSelectedFilePath(keys[0] as string);
                    }
                }}
              />
            </Sider>
            <Content style={{ padding: '16px 24px', minHeight: 400, display: 'flex', flexDirection: 'column' }}>
                <Row justify="space-between" align="middle" style={{ marginBottom: 16, flexWrap: 'wrap', gap: '10px' }}>
                    <Title level={5} style={{ margin: 0 }}>Findings in: {selectedFilePath || "..."}</Title>
                    <Space wrap>
                        <Button size="small" onClick={() => setActiveFindingKeys(filteredAndSortedFindings.map(f => f.id.toString()))} icon={<PlusSquareOutlined />}>Expand All</Button>
                        <Button size="small" onClick={() => setActiveFindingKeys([])} icon={<MinusSquareOutlined />}>Collapse All</Button>
                    </Space>
                </Row>
                
                <div style={{ flexGrow: 1, overflowY: 'auto' }}>
                    {Object.entries(groupedFindings).map(([groupName, findingsInGroup]) => (
                      <React.Fragment key={groupName}>
                        {groupBy !== 'none' && (
                          <Divider orientation="left">
                             <Tag color="purple">{`${groupBy.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}: ${groupName}`}</Tag>
                          </Divider>
                        )}
                        {findingsInGroup.length > 0 ? (
                            <FindingList 
                                findings={findingsInGroup} 
                                activeKeys={activeFindingKeys}
                                onActiveKeyChange={(keys) => setActiveFindingKeys(keys as string[])}
                            />
                        ) : (
                            <Empty description="No findings match the current filter criteria." />
                        )}
                      </React.Fragment>
                    ))}
                </div>
            </Content>
        </Layout>

        {isRemediationComplete && selectedFilePath && (
          <div style={{ padding: '16px 24px 24px 24px' }}>
            <FileMergeExplanations findings={allFindingsInFile} />
            <EnhancedDiffViewer
               title={`Full File Diff: ${selectedFilePath}`}
                oldCode={originalCode}
                newCode={fixedCode}
                filePath={selectedFilePath}
            />
          </div>
        )}
      </Layout>
    </Layout>
  );
};

export default ResultsPage;