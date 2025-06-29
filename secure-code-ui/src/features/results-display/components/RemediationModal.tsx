// src/app/components/RemediationModal.tsx

import { RocketOutlined } from '@ant-design/icons';
import { Alert, Checkbox, Modal, Space, Typography } from 'antd';
import React, { useMemo, useState } from 'react';

type CheckboxValueType = string | number;

const { Text, Paragraph } = Typography;

// A simplified finding structure for this component's needs
interface FindingStub {
  cwe?: string;
}

interface RemediationModalProps {
  open: boolean;
  isLoading: boolean;
  findings: FindingStub[];
  onCancel: () => void;
  onSubmit: (categories: string[]) => void;
}

// A mapping from CWEs to their corresponding Agent names (categories)
// This should ideally be derived from a central configuration, but is sufficient for now.
const CWE_TO_AGENT_MAP: { [key: string]: string } = {
    'CWE-22': 'FileHandlingAgent',
    'CWE-79': 'ValidationAgent',
    'CWE-89': 'ValidationAgent',
    'CWE-287': 'AuthenticationAgent',
    'CWE-306': 'AccessControlAgent',
    'CWE-352': 'SessionManagementAgent',
    'CWE-327': 'CryptographyAgent',
    'CWE-502': 'CodeIntegrityAgent',
    'CWE-78': 'ValidationAgent',
    'CWE-862': 'AccessControlAgent',
    'CWE-863': 'AccessControlAgent'
    // This map can be expanded
};

const getAgentNameForFinding = (finding: FindingStub): string | null => {
    if (finding.cwe && CWE_TO_AGENT_MAP[finding.cwe]) {
        return CWE_TO_AGENT_MAP[finding.cwe];
    }
    // Add more complex mapping logic here if needed
    return 'ValidationAgent'; // Default fallback agent
}


const RemediationModal: React.FC<RemediationModalProps> = ({ open, isLoading, findings, onCancel, onSubmit }) => {
  const [selectedCategories, setSelectedCategories] = useState<CheckboxValueType[]>([]);

  const availableCategories = useMemo(() => {
    const categories = new Set<string>();
    findings.forEach(finding => {
        const agentName = getAgentNameForFinding(finding);
        if(agentName) {
            categories.add(agentName);
        }
    });
    return Array.from(categories);
  }, [findings]);
  
  const handleOk = () => {
    onSubmit(selectedCategories as string[]);
  };

  const onCheckboxChange = (checkedValues: CheckboxValueType[]) => {
    setSelectedCategories(checkedValues);
  };

  return (
    <Modal
      title={
        <Space>
            <RocketOutlined />
            Begin Remediation
        </Space>
    }
      open={open}
      onOk={handleOk}
      onCancel={onCancel}
      confirmLoading={isLoading}
      okText="Start Remediation"
      okButtonProps={{ disabled: selectedCategories.length === 0 }}
      destroyOnClose
    >
      <Paragraph>
        Select the categories of vulnerabilities you would like the AI to attempt to fix. The system will apply fixes sequentially.
      </Paragraph>
      <Alert
        message="This is an experimental feature. Please review all generated code carefully before deployment."
        type="warning"
        showIcon
        style={{ marginBottom: 24 }}
      />
      <Text strong>Available Vulnerability Categories:</Text>
      <div style={{ marginTop: 8, border: '1px solid #f0f0f0', padding: 16, borderRadius: '8px' }}>
      <Checkbox.Group
        style={{ width: '100%' }}
        onChange={onCheckboxChange}
        value={selectedCategories}
      >
        <Space direction="vertical">
          {availableCategories.length > 0 ? (
            availableCategories.map(category => (
              <Checkbox key={category} value={category}>
                {category.replace('Agent', ' Issues')}
              </Checkbox>
            ))
          ) : (
            <Text type="secondary">No actionable categories found in this scan.</Text>
          )}
        </Space>
      </Checkbox.Group>
      </div>
    </Modal>
  );
};

export default RemediationModal;