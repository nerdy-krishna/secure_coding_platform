// src/components/FileTree.tsx
import { FileOutlined, FolderTwoTone } from "@ant-design/icons"; // Use FolderTwoTone for color
import { Button, Space, Tree, Typography } from "antd";
import type { DataNode } from "antd/es/tree";
import React, { useEffect, useMemo, useState } from "react";
import "./FileTree.css"; // <-- Import a new CSS file for custom styles

const { Text } = Typography;

interface IntermediateNode {
  title: string;
  key: React.Key;
  isLeaf: boolean;
  children: Record<string, IntermediateNode>;
}

type IntermediateTree = Record<string, IntermediateNode>;

interface FileTreeProps {
  files: string[];
  checkedKeys: React.Key[];
  onCheck: (
    checkedKeys: React.Key[] | { checked: React.Key[]; halfChecked: React.Key[] },
  ) => void;
}

const buildTree = (paths: string[]): { treeData: DataNode[], folderKeys: React.Key[], allKeys: React.Key[] } => {
  const root: IntermediateTree = {};
  const folderKeys: React.Key[] = [];
  const allKeys: React.Key[] = [];

  for (const path of paths) {
    const parts = path.split('/').filter(p => p);
    let currentLevel = root;

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      const isLeaf = i === parts.length - 1;
      const currentPath = parts.slice(0, i + 1).join('/');

      if (!currentLevel[part]) {
        allKeys.push(currentPath); // Add every key (file or folder) to allKeys
        if (!isLeaf) {
          folderKeys.push(currentPath);
        }
        currentLevel[part] = {
          title: part,
          key: currentPath,
          isLeaf: isLeaf,
          children: {},
        };
      }
      
      currentLevel = currentLevel[part].children;
    }
  }

  const convertToAntdFormat = (node: IntermediateTree): DataNode[] => {
    const sortedNodes = Object.values(node).sort((a, b) => {
      // If one is a folder and the other is a file, the folder comes first.
      if (a.isLeaf !== b.isLeaf) {
        return a.isLeaf ? 1 : -1;
      }
      // Otherwise, sort alphabetically by title.
      return a.title.localeCompare(b.title);
    });

    return sortedNodes.map((n: IntermediateNode) => ({
      title: <span className={!n.isLeaf ? 'folder-title' : 'file-title'}>{n.title}</span>,
      key: n.key,
      isLeaf: n.isLeaf,
      icon: n.isLeaf ? <FileOutlined /> : <FolderTwoTone twoToneColor="#1677ff" />,
      children: n.children ? convertToAntdFormat(n.children) : undefined,
    }));
  };

  return { treeData: convertToAntdFormat(root), folderKeys, allKeys };
};


const FileTree: React.FC<FileTreeProps> = ({
  files,
  checkedKeys,
  onCheck,
}) => {
  const { treeData, folderKeys, allKeys } = useMemo(() => buildTree(files), [files]);
  const [expandedKeys, setExpandedKeys] = useState<React.Key[]>(folderKeys);
  
  useEffect(() => {
    setExpandedKeys(folderKeys);
  }, [files, folderKeys]);


  if (files.length === 0) {
    return null;
  }

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
        <Text strong>Select Files for Analysis</Text>
        <Space wrap>
            <Button type="primary" size="small" onClick={() => onCheck(allKeys)}>Select All</Button>
            <Button type="primary" ghost size="small" onClick={() => onCheck([])}>Deselect All</Button>
            <Button type="primary" size="small" onClick={() => setExpandedKeys(folderKeys)}>Expand All</Button>
            <Button type="primary" ghost size="small" onClick={() => setExpandedKeys([])}>Collapse All</Button>
        </Space>
      </div>
      <div
        style={{
          border: "1px solid #d9d9d9",
          borderRadius: "8px",
          padding: "8px",
          marginTop: "8px",
          maxHeight: "400px",
          overflow: "auto",
        }}
      >
        <Tree
          checkable
          showIcon
          expandAction="click"
          onCheck={onCheck}
          checkedKeys={checkedKeys}
          treeData={treeData}
          expandedKeys={expandedKeys}
          onExpand={(keys) => setExpandedKeys(keys)}
        />
      </div>
    </>
  );
};

export default FileTree;