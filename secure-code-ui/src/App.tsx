// secure-code-ui/src/App.tsx
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import React from "react";
import {
  Navigate,
  Outlet,
  Route,
  BrowserRouter as Router,
  Routes,
} from "react-router-dom";

import { AuthProvider } from "./contexts/AuthProvider";
import { useAuth } from "./hooks/useAuth";

// Layouts
import AuthLayout from "./layouts/AuthLayout";
import DashboardLayout from "./layouts/DashboardLayout";

// Page Components
import LoginPage from "./pages/auth/LoginPage";
import RegisterPage from "./pages/auth/RegisterPage";
import DashboardPage from "./pages/dashboard/DashboardPage";
import LLMSettingsPage from "./pages/dashboard/LLMSettingsPage";
import SettingsPage from "./pages/dashboard/SettingsPage";
import SubmissionHistoryPage from "./pages/dashboard/SubmissionHistoryPage";
import UserProfilePage from "./pages/dashboard/UserProfilePage";
import ResultsPage from "./pages/ResultsPage";
import SubmitCodePage from "./pages/SubmitCodePage";

// Placeholder Pages
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

// Wrapper for regular authenticated user routes
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

// Wrapper for public auth routes (login/register)
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

// Redirector for the root path
const RootRedirector: React.FC = () => {
  const { accessToken, initialAuthChecked, isLoading } = useAuth();

  if (!initialAuthChecked || isLoading) {
    return <div>Loading...</div>;
  }

  return accessToken ? (
    <Navigate to="/dashboard" replace />
  ) : (
    <Navigate to="/login" replace />
  );
};

// New Wrapper for Superuser-only routes
const SuperuserRoutesWithLayout: React.FC = () => {
  const { user, accessToken, initialAuthChecked, isLoading } = useAuth();

  if (!initialAuthChecked || isLoading) {
    return <div>Loading authentication status...</div>;
  }

  if (!accessToken) {
    return <Navigate to="/login" replace />;
  }

  // Redirect if user is not a superuser
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
        {/* Public auth routes */}
        <Route element={<AuthRoutesWithLayout />}>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
        </Route>

        {/* Protected routes for regular authenticated users */}
        <Route element={<ProtectedRoutesWithLayout />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/submit" element={<SubmitCodePage />} />
          <Route path="/history" element={<SubmissionHistoryPage />} />
          <Route path="/results/:submissionId" element={<ResultsPage />} />
          <Route path="/profile" element={<UserProfilePage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>

        {/* Protected routes for superusers only */}
        <Route element={<SuperuserRoutesWithLayout />}>
          <Route path="/settings/llm" element={<LLMSettingsPage />} />
        </Route>

        {/* Root and wildcard routes */}
        <Route path="/" element={<RootRedirector />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Router>
  );
}

// Create a react-query client instance
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