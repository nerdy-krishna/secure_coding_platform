// src/features/submission-history/components/ScanTimeline.tsx
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  SyncOutlined,
} from "@ant-design/icons";
import { Steps } from 'antd';
import React from 'react';
import type { ScanEventItem } from "../../../shared/types/api";

interface ScanTimelineProps {
  events: ScanEventItem[];
  currentStatus: string;
}

const STAGE_ORDER = ["QUEUED", "PENDING_COST_APPROVAL", "QUEUED_FOR_SCAN", "ANALYZING_CONTEXT", "RUNNING_AGENTS", "GENERATING_REPORTS", "COMPLETED", "FAILED", "CANCELLED", "REMEDIATION_COMPLETED"];
const STAGE_TITLES: { [key: string]: string } = {
    QUEUED: "Queued",
    PENDING_COST_APPROVAL: "Pending Approval",
    QUEUED_FOR_SCAN: "Queued for Scan",
    ANALYZING_CONTEXT: "Analyzing",
    RUNNING_AGENTS: "Running Agents",
    GENERATING_REPORTS: "Reporting",
    COMPLETED: "Completed",
    REMEDIATION_COMPLETED: "Completed",
    FAILED: "Failed",
    CANCELLED: "Cancelled",
};

// Define a specific type for the Step status
type StepStatus = 'wait' | 'process' | 'finish' | 'error';

const getStageInfo = (stage: string, events: ScanEventItem[], currentStatus: string): { status: StepStatus; icon: React.ReactNode } => {
    const stageIndex = STAGE_ORDER.indexOf(stage);
    const currentStatusIndex = STAGE_ORDER.indexOf(currentStatus);
    const event = events.find(e => e.stage_name === stage);

    const isFinished = currentStatus === "COMPLETED" || currentStatus === "REMEDIATION_COMPLETED";
    const isFailedOrCancelled = currentStatus === "FAILED" || currentStatus === "CANCELLED";

    if (isFinished && stageIndex <= STAGE_ORDER.indexOf("COMPLETED")) {
        // If the scan is complete, all visible stages are marked as finished.
        return { status: 'finish', icon: <CheckCircleOutlined /> };
    }
    
    if (isFailedOrCancelled) {
        if (stage === currentStatus) return { status: 'error', icon: <CloseCircleOutlined /> };
        if (event) return { status: 'finish', icon: <CheckCircleOutlined /> };
        return { status: 'wait', icon: null };
    }
    
    if (stageIndex < currentStatusIndex) {
        return { status: 'finish', icon: <CheckCircleOutlined /> };
    }
    if (stageIndex === currentStatusIndex) {
        return { status: 'process', icon: <SyncOutlined spin /> };
    }
    
    return { status: 'wait', icon: null };
};

const ScanTimeline: React.FC<ScanTimelineProps> = ({ events, currentStatus }) => {
  const visibleStages = ["QUEUED", "ANALYZING_CONTEXT", "RUNNING_AGENTS", "GENERATING_REPORTS", "COMPLETED"];
  
  if (currentStatus === "PENDING_COST_APPROVAL") return null;

  return (
    <div style={{ padding: '16px 8px 8px' }}>
      <Steps size="small" current={STAGE_ORDER.indexOf(currentStatus)} status={currentStatus === "FAILED" ? "error" : "process"}>
        {visibleStages.map(stage => {
          const { status, icon } = getStageInfo(stage, events, currentStatus);
          const title = STAGE_TITLES[stage] || stage;
          const event = events.find(e => e.stage_name === stage);
          return (
            <Steps.Step 
                key={stage} 
                title={<span style={{fontSize: '12px'}}>{title}</span>}
                status={status}
                icon={icon}
                description={event ? new Date(event.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}
            />
          );
        })}
      </Steps>
    </div>
  );
};

export default ScanTimeline;