import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";
import {
  Navigate,
  Outlet,
  Route,
  BrowserRouter as Router,
  Routes,
} from "react-router-dom";
import { useAuth } from "../shared/hooks/useAuth";
import { AuthProvider } from "./providers/AuthProvider";

import AuthLayout from "../widgets/AuthLayout";
import DashboardLayout from "../widgets/DashboardLayout";

import LLMSettingsPage from "../features/admin-settings/components/LLMSettingsPage";
import RegisterPage from "../features/authentication/components/RegisterPage";
import CostUsagePage from "../pages/account/CostUsagePage";
import DashboardPage from "../pages/account/DashboardPage";
import SettingsPage from "../pages/account/SettingsPage";
import SubmissionHistoryPage from "../pages/account/SubmissionHistoryPage";
import UserProfilePage from "../pages/account/UserProfilePage";
import AnalysisResultsIndexPage from "../pages/analysis/AnalysisResultsIndexPage";
import ExecutiveSummaryPage from "../pages/analysis/ExecutiveSummaryPage";
import ResultsPage from '../pages/analysis/ResultsPage';
import LoginPage from "../pages/auth/LoginPage";
import SubmitCodePage from "../pages/submission/SubmitCodePage";

const NotFoundPage: React.FC = () => (
  <div style={{ textAlign: "center", marginTop: "50px", padding: "20px" }}>
    <h1>404 - Page Not Found</h1>
    <p>Sorry, the page you are looking for does not exist.</p>
    <button
      onClick={() => window.history.back()}
      style={{ padding: "10px 15px", marginTop: "15px", cursor: "pointer" }}
    >
      Go Back
    </button>
  </div>
);

const ProtectedRoutesWithLayout: React.FC = () => {
  const { accessToken, initialAuthChecked, isLoading } = useAuth();
  if (!initialAuthChecked || isLoading) {
    return <div>Loading authentication status...</div>;
  }

  if (!accessToken) {
    return <Navigate to="/login" replace />;
  }
  return (
    <DashboardLayout>
      <Outlet />
    </DashboardLayout>
  );
};

const AuthRoutesWithLayout: React.FC = () => {
  const { accessToken, initialAuthChecked, isLoading } = useAuth();
  if (!initialAuthChecked || isLoading) {
    return <div>Loading authentication status...</div>;
  }

  if (accessToken) {
    return <Navigate to="/" replace />;
  }
  return (
    <AuthLayout>
      <Outlet />
    </AuthLayout>
  );
};

const RootRedirector: React.FC = () => {
  const { accessToken, initialAuthChecked, isLoading } = useAuth();
  if (!initialAuthChecked || isLoading) {
    return <div>Loading...</div>;
  }

  return accessToken ? (
    <Navigate to="/account/dashboard" replace />
  ) : (
    <Navigate to="/login" replace />
  );
};

const SuperuserRoutesWithLayout: React.FC = () => {
  const { user, accessToken, initialAuthChecked, isLoading } = useAuth();
  if (!initialAuthChecked || isLoading) {
    return <div>Loading authentication status...</div>;
  }

  if (!accessToken) {
    return <Navigate to="/login" replace />;
  }

  if (!user?.is_superuser) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <DashboardLayout>
      <Outlet />
    </DashboardLayout>
  );
};

function AppContent() {
  return (
    <Router>
      <Routes>
        <Route element={<AuthRoutesWithLayout />}>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
        </Route>

        <Route element={<ProtectedRoutesWithLayout />}>
          <Route path="/account/dashboard" element={<DashboardPage />} />
          <Route path="/submission/submit" element={<SubmitCodePage />} />
          <Route path="/analysis/results" element={<AnalysisResultsIndexPage />} />
          <Route path="/analysis/results/:scanId" element={<ResultsPage />} />
          <Route path="/scans/:scanId/executive-summary" element={<ExecutiveSummaryPage />} />
          <Route path="/account/history" element={<SubmissionHistoryPage />} />
          <Route path="/account/usage" element={<CostUsagePage />} />
          <Route path="/account/profile" element={<UserProfilePage />} />
          <Route path="/account/settings" element={<SettingsPage />} />
        </Route>

        <Route element={<SuperuserRoutesWithLayout />}>
          <Route path="/account/settings/llm" element={<LLMSettingsPage />} />
        </Route>

        <Route path="/" element={<RootRedirector />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Router>
  );
}

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;