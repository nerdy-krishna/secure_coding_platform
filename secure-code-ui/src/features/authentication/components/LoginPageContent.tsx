// secure-code-ui/src/features/authentication/components/LoginPageContent.tsx
//
// SCCAP login form. Native inputs; useAuth() login wiring unchanged.

import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../../../shared/hooks/useAuth";
import { type UserLoginData } from "../../../shared/types/api";
import { Icon } from "../../../shared/ui/Icon";
import { useToast } from "../../../shared/ui/Toast";

const LoginPageContent: React.FC = () => {
  const {
    login,
    error: authError,
    isLoading: authLoading,
    clearError,
  } = useAuth();
  const toast = useToast();

  const [form, setForm] = useState<UserLoginData & { remember: boolean }>({
    username: "",
    password: "",
    remember: true,
  });

  useEffect(() => {
    if (authError) {
      toast.error(authError);
      clearError();
    }
  }, [authError, clearError, toast]);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.username || !form.password) return;
    try {
      await login({ username: form.username, password: form.password });
    } catch (err) {
      console.error("LoginPage: login failed:", err);
    }
  };

  return (
    <form
      onSubmit={onSubmit}
      className="surface"
      style={{ padding: 32, display: "grid", gap: 16 }}
    >
      <div style={{ textAlign: "center", marginBottom: 4 }}>
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 10,
            color: "var(--fg)",
            fontSize: 20,
            fontWeight: 600,
          }}
        >
          <Icon.Shield size={22} color="var(--primary)" /> SCCAP
        </div>
        <div
          style={{
            color: "var(--fg-muted)",
            fontSize: 12.5,
            marginTop: 4,
          }}
        >
          Secure Coding & Compliance Automation Platform
        </div>
      </div>

      <label style={{ display: "grid", gap: 6 }}>
        <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
          Username or email
        </span>
        <div className="input-with-icon">
          <Icon.User size={14} />
          <input
            className="sccap-input"
            placeholder="you@example.com"
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            required
            autoFocus
            autoComplete="username"
            style={{ paddingLeft: 32 }}
          />
        </div>
      </label>

      <label style={{ display: "grid", gap: 6 }}>
        <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>Password</span>
        <div className="input-with-icon">
          <Icon.Lock size={14} />
          <input
            className="sccap-input"
            type="password"
            placeholder="••••••••"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            required
            autoComplete="current-password"
            style={{ paddingLeft: 32 }}
          />
        </div>
      </label>

      <label
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 8,
          fontSize: 13,
          color: "var(--fg-muted)",
          cursor: "pointer",
        }}
      >
        <input
          type="checkbox"
          checked={form.remember}
          onChange={(e) => setForm({ ...form, remember: e.target.checked })}
          style={{ accentColor: "var(--primary)" }}
        />
        Remember me
      </label>

      <button
        type="submit"
        className="sccap-btn sccap-btn-primary sccap-btn-lg"
        disabled={authLoading}
        style={{ width: "100%" }}
      >
        {authLoading ? "Signing in…" : "Log in"}
      </button>

      <div style={{ textAlign: "center", fontSize: 12.5 }}>
        <Link
          to="/forgot-password"
          style={{ color: "var(--primary)", textDecoration: "none" }}
        >
          Forgot password?
        </Link>
      </div>
    </form>
  );
};

export default LoginPageContent;
