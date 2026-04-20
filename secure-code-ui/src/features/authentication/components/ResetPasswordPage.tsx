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
  const token = new URLSearchParams(location.search).get("token");

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!token) {
      toast.error("Invalid or missing reset token.");
    }
  }, [token, toast]);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) {
      toast.error("No token provided.");
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
      style={{ padding: 32, display: "grid", gap: 16 }}
    >
      <h2
        style={{
          textAlign: "center",
          color: "var(--fg)",
          marginBottom: 8,
        }}
      >
        Set a new password
      </h2>
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
