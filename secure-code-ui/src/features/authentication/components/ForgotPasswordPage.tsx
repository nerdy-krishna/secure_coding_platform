// secure-code-ui/src/features/authentication/components/ForgotPasswordPage.tsx
//
// SCCAP password-reset request. Native form; authService.forgotPassword
// unchanged.

import React, { useState } from "react";
import { Link } from "react-router-dom";
import { authService } from "../../../shared/api/authService";
import { Icon } from "../../../shared/ui/Icon";
import { useToast } from "../../../shared/ui/Toast";

const ForgotPasswordPage: React.FC = () => {
  const toast = useToast();
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;
    setLoading(true);
    try {
      await authService.forgotPassword(email);
      setSuccess(true);
      toast.success("Password reset email sent (if an account exists).");
    } catch {
      toast.error("Failed to request password reset.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="surface" style={{ padding: 32 }}>
      <h2 style={{ textAlign: "center", color: "var(--fg)", marginBottom: 8 }}>
        Forgot password
      </h2>
      {success ? (
        <div style={{ textAlign: "center", display: "grid", gap: 12 }}>
          <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>
            If an account exists for that email, a password reset link has been
            sent.
          </div>
          <Link
            to="/login"
            style={{
              color: "var(--primary)",
              fontSize: 13,
              textDecoration: "none",
            }}
          >
            Return to login
          </Link>
        </div>
      ) : (
        <form onSubmit={onSubmit} style={{ display: "grid", gap: 16 }}>
          <div
            style={{
              textAlign: "center",
              fontSize: 13,
              color: "var(--fg-muted)",
              lineHeight: 1.5,
            }}
          >
            Enter your email address and we'll send you a link to reset your
            password.
          </div>
          <div className="input-with-icon">
            <Icon.Mail size={14} />
            <input
              className="sccap-input"
              type="email"
              placeholder="Email address"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoFocus
              style={{ paddingLeft: 32 }}
            />
          </div>
          <button
            type="submit"
            className="sccap-btn sccap-btn-primary sccap-btn-lg"
            disabled={loading}
            style={{ width: "100%" }}
          >
            {loading ? "Sending…" : "Send reset link"}
          </button>
          <div style={{ textAlign: "center", fontSize: 12.5 }}>
            <Link
              to="/login"
              style={{ color: "var(--primary)", textDecoration: "none" }}
            >
              Back to login
            </Link>
          </div>
        </form>
      )}
    </div>
  );
};

export default ForgotPasswordPage;
