import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, Outlet } from 'react-router-dom';

import AuthLayout from './layouts/AuthLayout';
import DashboardLayout from './layouts/DashboardLayout';

import LoginPage from './pages/auth/LoginPage';
import RegisterPage from './pages/auth/RegisterPage';
import DashboardPage from './pages/dashboard/DashboardPage';
// Import other pages as you create them
// e.g., import SubmitCodePage from './pages/dashboard/SubmitCodePage';
// import HistoryPage from './pages/dashboard/HistoryPage';
// import ProfilePage from './pages/dashboard/ProfilePage';
// import SettingsPage from './pages/dashboard/SettingsPage';


// Placeholder for authentication status (replace with actual auth logic later)
const isAuthenticated = () => {
  return !!localStorage.getItem('authToken'); // Example
};

// Wrapper for routes that need the DashboardLayout
const ProtectedRoutesWithLayout: React.FC = () => {
  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />;
  }
  return (
    <DashboardLayout>
      <Outlet /> {/* Child routes will render here */}
    </DashboardLayout>
  );
};

// Wrapper for routes that need the AuthLayout
const AuthRoutesWithLayout: React.FC = () => {
  if (isAuthenticated()) {
    return <Navigate to="/dashboard" replace />;
  }
  return (
    <AuthLayout>
      <Outlet /> {/* Child routes will render here */}
    </AuthLayout>
  );
};


function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Authentication Routes (Login, Register) */}
        <Route element={<AuthRoutesWithLayout />}>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
        </Route>

        {/* Protected Dashboard Routes */}
        <Route element={<ProtectedRoutesWithLayout />}>
          <Route path="/dashboard" element={<DashboardPage />} />
          {/* Add other dashboard pages as children here */}
          {/* Example:
          <Route path="/dashboard/submit" element={<SubmitCodePage />} />
          <Route path="/dashboard/history" element={<HistoryPage />} />
          <Route path="/dashboard/profile" element={<ProfilePage />} />
          <Route path="/dashboard/settings" element={<SettingsPage />} />
          */}
        </Route>

        {/* Redirect logic for root path */}
        <Route
          path="/"
          element={
            isAuthenticated() ? (
              <Navigate to="/dashboard" replace />
            ) : (
              <Navigate to="/login" replace />
            )
          }
        />

        {/* Fallback for unmatched routes */}
        <Route path="*" element={<Navigate to={isAuthenticated() ? "/dashboard" : "/login"} replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;