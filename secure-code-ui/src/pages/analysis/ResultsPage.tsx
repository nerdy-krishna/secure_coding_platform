import { useQuery } from '@tanstack/react-query';
import { Alert, Spin } from 'antd';
import React from 'react';
import { useParams } from 'react-router-dom';
import { scanService } from '../../shared/api/scanService';
import AuditRunPage from './AuditRunPage';
import RemediationRunPage from './RemediationRunPage';

const ResultsPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();

  const { data: scanType, isLoading, isError, error } = useQuery({
    queryKey: ['scanResult', scanId, 'type'],
    queryFn: async () => {
      if (!scanId) throw new Error('Scan ID is missing');
      const result = await scanService.getScanResult(scanId);
      // Ensure a default value if scan_type is missing
      return result?.summary_report?.scan_type ?? 'audit'; 
    },
    enabled: !!scanId,
  });

  if (isLoading) {
    return <Spin tip="Determining result type..." style={{ display: 'block', marginTop: '50px' }} />;
  }

  if (isError) {
    return <Alert message="Error" description={error.message} type="error" showIcon />;
  }

  // Check for remediation types to render the correct page
  if (scanType === 'REMEDIATE' || scanType === 'DIRECT_REMEDIATE') {
    return <RemediationRunPage />;
  }

  return <AuditRunPage />;
};

export default ResultsPage;