// secure-code-ui/src/features/authentication/components/ResetPasswordPage.tsx
//
// SCCAP set-new-password form. Wiring to authService.resetPassword
// unchanged.

import React, { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { authService } from "../../../shared/api/authService";
import { Icon } from "../../../shared/ui/Icon";
import { useToast } from "../../../shared/ui/Toast";

const ResetPasswordPage: React.FC = () => {
  const toast = useToast();
  const navigate = useNavigate();
  const location = useLocation();
  // SECURITY (V15.1.5 dangerous functionality): token is a one-shot reset credential. It SHOULD NOT be logged, retained in localStorage, or kept in URL after submit. See remediation below for history.replaceState scrub.
  const token = new URLSearchParams(location.search).get("token");

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!token) {
      toast.error("Invalid or missing reset token.");
      return;
    }
    window.history.replaceState({}, document.title, '/reset-password');
  }, [token, toast]);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) {
      toast.error("No token provided.");
      return;
    }
    if (password.length > 128) {
      toast.error("Password too long.");
      return;
    }
    if (!password || password !== confirm) {
      toast.error("The two passwords do not match.");
      return;
    }
    setLoading(true);
    try {
      await authService.resetPassword(token, password);
      toast.success("Password secured. You can now log in.");
      navigate("/login");
    } catch {
      toast.error("Failed to reset password. The link might be expired.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form
      onSubmit={onSubmit}
      className="surface"
      style={{
        padding: 36,
        display: "grid",
        gap: 16,
        boxShadow: "var(--shadow-md)",
        position: "relative",
        overflow: "hidden",
      }}
    >
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
            width: 48,
            height: 48,
            borderRadius: 12,
            background: "var(--primary-weak)",
            color: "var(--primary)",
            marginBottom: 12,
          }}
        >
          <Icon.Key size={22} />
        </div>
        <div
          style={{
            fontSize: 20,
            fontWeight: 600,
            color: "var(--fg)",
            letterSpacing: "-0.01em",
          }}
        >
          Set a new password
        </div>
      </div>
      <div
        style={{
          textAlign: "center",
          fontSize: 13,
          color: "var(--fg-muted)",
          lineHeight: 1.5,
        }}
      >
        Please enter your new password below.
      </div>
      <div className="input-with-icon">
        <Icon.Lock size={14} />
        <input
          className="sccap-input"
          type="password"
          placeholder="New password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          autoFocus
          autoComplete="new-password"
          maxLength={128}
          style={{ paddingLeft: 32 }}
        />
      </div>
      <div className="input-with-icon">
        <Icon.Lock size={14} />
        <input
          className="sccap-input"
          type="password"
          placeholder="Confirm password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          required
          autoComplete="new-password"
          maxLength={128}
          style={{ paddingLeft: 32 }}
        />
      </div>
      <button
        type="submit"
        className="sccap-btn sccap-btn-primary sccap-btn-lg"
        disabled={loading || !token}
        style={{ width: "100%" }}
      >
        {loading ? "Saving…" : "Reset password"}
      </button>
    </form>
  );
};

export default ResetPasswordPage;
