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

import LLMSettingsPage from "../features/admin-settings/components/LLMSettingsPage";
import DashboardPage from "../pages/account/DashboardPage";
import SettingsPage from "../pages/account/SettingsPage";
import SubmissionHistoryPage from "../pages/account/SubmissionHistoryPage";
import UserProfilePage from "../pages/account/UserProfilePage";
import SystemConfigTab from "../pages/admin/SystemConfigTab";
import UserManagementTab from "../pages/admin/UserManagement";
import SMTPSettingsTab from "../pages/admin/SMTPSettingsTab";
import AgentManagementPage from "../pages/admin/AgentManagementPage";
import FrameworkManagementPage from '../pages/admin/FrameworkManagementPage';
import PromptManagementPage from '../pages/admin/PromptManagementPage';
import RAGManagementPage from '../pages/admin/RAGManagementPage';
import ExecutiveSummaryPage from "../pages/analysis/ExecutiveSummaryPage";
import LlmLogViewerPage from '../pages/analysis/LlmLogViewerPage';
import ProjectsPage from "../pages/analysis/ProjectsPage";
import ResultsPage from '../pages/analysis/ResultsPage';
import LoginPage from "../pages/auth/LoginPage";
import SecurityAdvisorPage from "../pages/chat/SecurityAdvisorPage";
import SubmitCodePage from "../pages/submission/SubmitCodePage";
import SetupPage from "../pages/setup/SetupPage";
import AuthLayout from "../widgets/AuthLayout";
import DashboardLayout from "../widgets/DashboardLayout";

const NotFoundPage: React.FC = () => (
  <div style= {{ textAlign: "center", marginTop: "50px", padding: "20px" }}>
    <h1>404 - Page Not Found </h1>
      < p > Sorry, the page you are looking for does not exist.</p>
        < button
      onClick = {() => window.history.back()}
style = {{ padding: "10px 15px", marginTop: "15px", cursor: "pointer" }}
    >
  Go Back
    </button>
    </div>
);

const LoadingScreen: React.FC = () => (
  <div style= {{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh", flexDirection: "column" }}>
    <h2>Connecting to Services...</h2>
      < p > Please wait while the Secure Coding Platform is starting up.</p>
        </div>
);

const ProtectedRoutesWithLayout: React.FC = () => {
  const { accessToken, initialAuthChecked, isLoading, isSetupCompleted } = useAuth();
  if (!initialAuthChecked || isLoading || isSetupCompleted === null) {
    return <LoadingScreen />;
  }

  if (isSetupCompleted === false) {
    return <Navigate to="/setup" replace />;
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

import ForgotPasswordPage from "../features/authentication/components/ForgotPasswordPage";
import ResetPasswordPage from "../features/authentication/components/ResetPasswordPage";

const AuthRoutesWithLayout: React.FC = () => {
  const { accessToken, initialAuthChecked, isLoading, isSetupCompleted } = useAuth();
  if (!initialAuthChecked || isLoading || isSetupCompleted === null) {
    return <LoadingScreen />;
  }

  // Force redirect to setup if not completed
  if (isSetupCompleted === false) {
    return <Navigate to="/setup" replace />;
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
  const { accessToken, initialAuthChecked, isLoading, isSetupCompleted } = useAuth();
  if (!initialAuthChecked || isLoading || isSetupCompleted === null) {
    return <LoadingScreen />;
  }

  if (isSetupCompleted === false) {
    return <Navigate to="/setup" replace />;
  }

  return accessToken ? (
    <Navigate to= "/account/dashboard" replace />
  ) : (
  <Navigate to= "/login" replace />
  );
};

const SuperuserRoutesWithLayout: React.FC = () => {
  const { user, accessToken, initialAuthChecked, isLoading, isSetupCompleted } = useAuth();
  if (!initialAuthChecked || isLoading || isSetupCompleted === null) {
    return <LoadingScreen />;
  }

  if (isSetupCompleted === false) {
    return <Navigate to="/setup" replace />;
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
    <Route element= {< AuthRoutesWithLayout />}>
      <Route path="/login" element = {< LoginPage />} />
        < Route path = "/forgot-password" element = {< ForgotPasswordPage />} />
          < Route path = "/reset-password" element = {< ResetPasswordPage />} />
            </Route>

{/* Setup Route */ }
<Route path="/setup" element = {< SetupPage />} />

  < Route element = {< ProtectedRoutesWithLayout />}>
    <Route path="/account/dashboard" element = {< DashboardPage />} />
      < Route path = "/submission/submit" element = {< SubmitCodePage />} />
        < Route path = "/analysis/results" element = {< ProjectsPage />} />
          < Route path = "/analysis/results/:scanId" element = {< ResultsPage />} />
            < Route path = "/scans/:scanId/executive-summary" element = {< ExecutiveSummaryPage />} />
              < Route path = "/scans/:scanId/llm-logs" element = {< LlmLogViewerPage />} />
                < Route path = "/advisor" element = {< SecurityAdvisorPage />} />
                  < Route path = "/account/history" element = {< SubmissionHistoryPage />} />
                    < Route path = "/account/profile" element = {< UserProfilePage />} />
                      < Route path = "/account/settings" element = {< SettingsPage />} />
                        </Route>

                        < Route element = {< SuperuserRoutesWithLayout />}>
                          <Route path="/admin/system" element = {< SystemConfigTab />} />
                            < Route path = "/admin/users" element = {< UserManagementTab />} />
                              < Route path = "/admin/smtp" element = {< SMTPSettingsTab />} />
                                < Route path = "/account/settings/llm" element = {< LLMSettingsPage />} />
                                  < Route path = "/admin/agents" element = {< AgentManagementPage />} />
                                    < Route path = "/admin/frameworks" element = {< FrameworkManagementPage />} />
                                      < Route path = "/admin/prompts" element = {< PromptManagementPage />} />
                                        < Route path = "/admin/rag" element = {< RAGManagementPage />} />
                                          </Route>

                                          < Route path = "/" element = {< RootRedirector />} />
                                            < Route path = "*" element = {< NotFoundPage />} />
                                              </Routes>
                                              </Router>
  );
}

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client= { queryClient } >
    <AuthProvider>
    <AppContent />
    </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;