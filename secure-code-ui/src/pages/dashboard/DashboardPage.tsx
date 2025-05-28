import React from "react";
import { Typography } from "antd";

const { Title } = Typography;

const DashboardPage: React.FC = () => {
  return (
    <div>
      <Title level={2}>Dashboard</Title>
      <p>Welcome to your Secure Coding Platform dashboard!</p>
      {/* Dashboard content will go here */}
    </div>
  );
};

export default DashboardPage;
