// secure-code-ui/src/features/authentication/components/LoginPageContent.tsx
//
// SCCAP login form. Uses the same design tokens / primitives as the rest
// of the app so light/dark × A/B variant switching from AuthLayout's
// floating toggle ripples through without extra wiring.

import React, { useEffect, useRef, useState } from "react";
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
  const lastSubmitRef = useRef<number>(0);
  const mountedAt = useRef<number>(Date.now());

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
    // V2.4.2: reject sub-750ms scripted submissions
    if (Date.now() - mountedAt.current < 750) return;
    // V2.2.1: enforce input length bounds
    if (!form.username || !form.password || form.username.length > 320 || form.password.length > 4096) {
      toast.error("Username or password is too long.");
      return;
    }
    // V2.4.1: client-side cooldown between submissions
    const now = Date.now();
    if (now - lastSubmitRef.current < 1500) {
      toast.error("Please wait before retrying.");
      return;
    }
    lastSubmitRef.current = now;
    try {
      await login({ username: form.username, password: form.password });
    } catch (err: unknown) {
      // V13.4.2 / V16.2.5: only log in dev; never expose raw error objects
      if (import.meta.env.DEV) {
        const sanitisedErr = err as { response?: { status?: number }; message?: string } | null;
        console.error("LoginPage: login failed:", {
          status: sanitisedErr?.response?.status,
          message: sanitisedErr?.message,
        });
      }
    }
  };

  return (
    <form
      onSubmit={onSubmit}
      className="surface"
      style={{
        padding: 36,
        display: "grid",
        gap: 18,
        boxShadow: "var(--shadow-md)",
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Top accent stripe picks up the active --primary. */}
      <div
        aria-hidden
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: 3,
          background:
            "linear-gradient(90deg, var(--primary) 0%, var(--accent) 100%)",
        }}
      />

      <div style={{ textAlign: "center" }}>
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            justifyContent: "center",
            width: 52,
            height: 52,
            borderRadius: 14,
            background: "var(--primary-weak)",
            color: "var(--primary)",
            marginBottom: 12,
          }}
        >
          <Icon.Shield size={26} />
        </div>
        <div
          style={{
            fontSize: 22,
            fontWeight: 600,
            color: "var(--fg)",
            letterSpacing: "-0.01em",
          }}
        >
          Welcome back
        </div>
        <div
          style={{
            color: "var(--fg-muted)",
            fontSize: 13,
            marginTop: 4,
          }}
        >
          Sign in to your SCCAP workspace.
        </div>
      </div>

      <label style={{ display: "grid", gap: 6 }}>
        <span style={{ fontSize: 12, color: "var(--fg-muted)", fontWeight: 500 }}>
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
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "baseline",
          }}
        >
          <span style={{ fontSize: 12, color: "var(--fg-muted)", fontWeight: 500 }}>
            Password
          </span>
          <Link
            to="/forgot-password"
            style={{
              color: "var(--primary)",
              fontSize: 11.5,
              textDecoration: "none",
            }}
          >
            Forgot?
          </Link>
        </div>
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
        Remember me on this device
      </label>

      <button
        type="submit"
        className="sccap-btn sccap-btn-primary sccap-btn-lg"
        disabled={authLoading}
        style={{ width: "100%" }}
      >
        {authLoading ? "Signing in…" : "Log in"}
        {!authLoading && <Icon.ArrowR size={14} />}
      </button>
    </form>
  );
};

export default LoginPageContent;
