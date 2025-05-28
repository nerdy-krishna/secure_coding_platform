// secure-code-ui/src/App.tsx
import React from "react";
import {
  Navigate,
  Outlet,
  Route,
  BrowserRouter as Router,
  Routes,
} from "react-router-dom";

import { AuthProvider } from "./contexts/AuthProvider"; // Import from the new AuthProvider.tsx file
import { useAuth } from "./hooks/useAuth";

// Layouts
import AuthLayout from "./layouts/AuthLayout";
import DashboardLayout from "./layouts/DashboardLayout";

// Page Components
import LoginPage from "./pages/auth/LoginPage";
import RegisterPage from "./pages/auth/RegisterPage";
import DashboardPage from "./pages/dashboard/DashboardPage";
import SettingsPage from "./pages/dashboard/SettingsPage";
import UserProfilePage from "./pages/dashboard/UserProfilePage";
import ResultsPage from "./pages/ResultsPage";
import SubmitCodePage from "./pages/SubmitCodePage";

// Placeholder Pages (as defined before)
const SubmissionHistoryPage: React.FC = () => (
  <div>
    <h2>Submission History</h2>
    <p>Your past submissions will appear here.</p>
    {/* You can add more placeholder content or styling as needed */}
  </div>
);

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

// Updated: Wrapper for routes that need the DashboardLayout (Protected Routes)
const ProtectedRoutesWithLayout: React.FC = () => {
  const { accessToken, initialAuthChecked, isLoading } = useAuth();

  if (!initialAuthChecked || isLoading) {
    // Show a loading spinner or a blank page while checking auth
    return <div>Loading authentication status...</div>; // Or a proper spinner component
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

// Updated: Wrapper for routes that need the AuthLayout (Public routes like Login/Register)
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

// RootRedirector component to handle root path redirection based on auth state
const RootRedirector: React.FC = () => {
  const { accessToken, initialAuthChecked, isLoading } = useAuth();

  if (!initialAuthChecked || isLoading) {
    return <div>Loading...</div>; // Or a global loading indicator
  }

  return accessToken ? (
    <Navigate to="/dashboard" replace />
  ) : (
    <Navigate to="/login" replace />
  );
};

function AppContent() {
  // Renamed old App to AppContent
  return (
    <Router>
      <Routes>
        <Route element={<AuthRoutesWithLayout />}>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
        </Route>

        <Route element={<ProtectedRoutesWithLayout />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/submit" element={<SubmitCodePage />} />
          <Route path="/history" element={<SubmissionHistoryPage />} />
          <Route path="/results/:submissionId" element={<ResultsPage />} />
          <Route path="/profile" element={<UserProfilePage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>

        <Route path="/" element={<RootRedirector />} />
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Router>
  );
}

// New App component that includes the AuthProvider
function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
