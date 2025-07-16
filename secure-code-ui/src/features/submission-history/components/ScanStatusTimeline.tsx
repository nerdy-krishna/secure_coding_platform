import {
  BarChartOutlined,
  CheckCircleFilled,
  CloseCircleFilled,
  FileSearchOutlined,
  HourglassOutlined,
  SlidersOutlined,
  SyncOutlined,
} from "@ant-design/icons";
import { Space, Tooltip, Typography } from "antd";
import React from "react";
import type { ScanEventItem } from "../../../shared/types/api";

const { Text } = Typography;

interface ScanStatusTimelineProps {
  events: ScanEventItem[];
  currentStatus: string;
}

const STAGE_ORDER = ["QUEUED", "ANALYZING_CONTEXT", "RUNNING_AGENTS", "GENERATING_REPORTS", "COMPLETED"];

const STAGE_CONFIG: { [key: string]: { icon: React.ReactNode; title: string } } = {
  QUEUED: { icon: <HourglassOutlined />, title: "Queued" },
  ANALYZING_CONTEXT: { icon: <SlidersOutlined />, title: "Analyzing" },
  RUNNING_AGENTS: { icon: <FileSearchOutlined />, title: "Running Agents" },
  GENERATING_REPORTS: { icon: <BarChartOutlined />, title: "Reporting" },
  COMPLETED: { icon: <CheckCircleFilled />, title: "Completed" },
};

const ScanStatusTimeline: React.FC<ScanStatusTimelineProps> = ({ events, currentStatus }) => {
  const stageEvents = new Map<string, ScanEventItem>();
  events.forEach(event => {
    stageEvents.set(event.stage_name, event);
  });
  
  const isFailed = currentStatus === "FAILED";
  const isCancelled = currentStatus === "CANCELLED";
  const currentStatusIndex = STAGE_ORDER.indexOf(currentStatus);
  const isOverallCompleted = currentStatus.includes("COMPLETED");

  return (
    <Space size="large" wrap style={{ marginTop: 16 }}>
      {STAGE_ORDER.map((stageKey, index) => {
        const event = stageEvents.get(stageKey);
        
        let icon = STAGE_CONFIG[stageKey].icon;
        let color = '#00000040'; // Default gray

        if (isOverallCompleted) {
            color = '#52c41a'; // All green if scan is complete
        } else if (isFailed || isCancelled) {
            color = event ? '#52c41a' : '#00000040'; // Green if it happened before failure
            if (currentStatus === stageKey) color = '#ff4d4f'; // Red for the failed stage
        } else { // In-progress states
            if (index < currentStatusIndex) {
                color = '#52c41a'; // Green for past stages
            } else if (index === currentStatusIndex) {
                color = '#1677ff'; // Blue for in-progress
                icon = <SyncOutlined spin />;
            }
        }

        if(stageKey === "COMPLETED" && (isFailed || isCancelled)) {
            icon = <CloseCircleFilled/>
            color = '#ff4d4f';
        } else if (stageKey === "COMPLETED" && stageEvents.has("COMPLETED")) {
            color = '#52c41a';
        }


        return (
          <Tooltip
            key={stageKey}
            title={
              <>
                <div>{STAGE_CONFIG[stageKey].title}</div>
                {event && <div>{new Date(event.timestamp).toLocaleString()}</div>}
              </>
            }
          >
            <Space direction="vertical" align="center" size={2}>
              <span style={{ fontSize: 24, color }}>{icon}</span>
              <Text style={{ fontSize: 11, color }}>{STAGE_CONFIG[stageKey].title}</Text>
            </Space>
          </Tooltip>
        );
      })}
    </Space>
  );
};

export default ScanStatusTimeline;