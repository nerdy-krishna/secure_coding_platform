// secure-code-ui/src/features/results-display/components/ResultsFileTree.tsx
import { FileOutlined, FolderTwoTone } from "@ant-design/icons";
import { Tag, Tree, Typography } from "antd";
import type { DataNode } from "antd/es/tree";
import React, { useMemo } from "react";
import { SeverityColors } from "../../../shared/lib/severityMappings";
import { type Finding, type SubmittedFile } from "../../../shared/types/api";
import "./ResultsFileTree.css";

const { Text } = Typography;

interface FileSeverity {
  highestSeverity: string;
  count: number;
}

const SEVERITY_ORDER: { [key: string]: number } = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFORMATIONAL: 1,
  NONE: 0,
};

const getHighestSeverity = (s1: string, s2: string): string => {
  return SEVERITY_ORDER[s1.toUpperCase()] > SEVERITY_ORDER[s2.toUpperCase()]
    ? s1
    : s2;
};

const buildSeverityMap = (
  findings: Finding[],
): { [path: string]: FileSeverity } => {
  const severityMap: { [path: string]: FileSeverity } = {};
  findings.forEach((finding) => {
    const path = finding.file_path;
    if (!path) return;
    const severity = finding.severity || "NONE";

    if (!severityMap[path]) {
      severityMap[path] = { highestSeverity: "NONE", count: 0 };
    }
    severityMap[path].highestSeverity = getHighestSeverity(
      severityMap[path].highestSeverity,
      severity,
    );
    severityMap[path].count++;
  });
  return severityMap;
};

interface IntermediateNode {
  title: string;
  key: string;
  isLeaf: boolean;
  children: Record<string, IntermediateNode>;
  highestSeverity: string;
  findingCount: number;
}

const buildTree = (
  paths: string[],
  severityMap: { [path: string]: FileSeverity },
): DataNode[] => {
  const root: Record<string, IntermediateNode> = {};

  paths.forEach((path) => {
    const parts = path.split("/").filter((p) => p);
    let currentLevel = root;
    let currentPath = "";

    parts.forEach((part, i) => {
      currentPath = i === 0 ? part : `${currentPath}/${part}`;
      const isLeaf = i === parts.length - 1;

      if (!currentLevel[part]) {
        currentLevel[part] = {
          title: part,
          key: currentPath,
          isLeaf,
          children: {},
          highestSeverity: "NONE",
          findingCount: 0,
        };
      }
      currentLevel = currentLevel[part].children;
    });
  });

  const aggregateSeverity = (
    node: IntermediateNode,
    path: string,
  ): [string, number] => {
    let highestSeverity = "NONE";
    let totalFindings = 0;

    if (node.isLeaf) {
      const fileSeverity = severityMap[path];
      if (fileSeverity) {
        highestSeverity = fileSeverity.highestSeverity;
        totalFindings = fileSeverity.count;
      }
    } else {
      Object.values(node.children).forEach((child) => {
        const childPath = `${path}/${child.title}`;
        const [childSeverity, childCount] = aggregateSeverity(child, childPath);
        highestSeverity = getHighestSeverity(highestSeverity, childSeverity);
        totalFindings += childCount;
      });
    }

    node.highestSeverity = highestSeverity;
    node.findingCount = totalFindings;
    return [highestSeverity, totalFindings];
  };

  Object.values(root).forEach((node) => aggregateSeverity(node, node.key));

  const convertToAntdFormat = (nodes: Record<string, IntermediateNode>): DataNode[] => {
    return Object.values(nodes)
      .sort((a, b) => {
        if (a.isLeaf !== b.isLeaf) return a.isLeaf ? 1 : -1;
        return a.title.localeCompare(b.title);
      })
      .map((n) => {
        const color =
          SeverityColors[n.highestSeverity.toUpperCase() as keyof typeof SeverityColors] || SeverityColors.NONE;

        return {
          key: n.key,
          icon: n.isLeaf ? (
            <FileOutlined style={{ color }} />
          ) : (
            <FolderTwoTone twoToneColor={color} />
          ),
          title: (
            <span className="tree-node-title">
              <Text style={{ color }}>{n.title}</Text>
              {n.findingCount > 0 && (
                <Tag color={color} className="finding-count-tag">
                  {n.findingCount}
                </Tag>
              )}
            </span>
          ),
          children: convertToAntdFormat(n.children),
        };
      });
  };

  return convertToAntdFormat(root);
};

interface ResultsFileTreeProps {
  analyzedFiles: SubmittedFile[];
  findings: Finding[];
  onSelect: (selectedKeys: React.Key[], info: { node: DataNode }) => void;
}

const ResultsFileTree: React.FC<ResultsFileTreeProps> = ({
  analyzedFiles,
  findings,
  onSelect,
}) => {
  const treeData = useMemo(() => {
    const filePaths = analyzedFiles.map((f) => f.file_path);
    const severityMap = buildSeverityMap(findings);
    return buildTree(filePaths, severityMap);
  }, [analyzedFiles, findings]);

  if (analyzedFiles.length === 0) {
    return <Text type="secondary">No files were analyzed.</Text>;
  }

  return (
    <Tree
      showIcon
      defaultExpandAll
      onSelect={onSelect}
      treeData={treeData}
      className="results-file-tree"
    />
  );
};

export default ResultsFileTree;