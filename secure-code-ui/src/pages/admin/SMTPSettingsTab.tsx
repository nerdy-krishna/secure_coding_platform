// secure-code-ui/src/pages/admin/SMTPSettingsTab.tsx
//
// SMTP outgoing-mail configuration. Data stays in the same system_config
// row (`system.smtp`); UI ports off antd to SCCAP primitives.

import React, { useEffect, useState } from "react";
import apiClient from "../../shared/api/apiClient";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";

const SMTP_CONFIG_KEY = "system.smtp";

interface SmtpSettings {
  host: string;
  port: number;
  user: string;
  password: string;
  from: string;
  tls: boolean;
  ssl: boolean;
}

interface SystemConfigRow {
  key: string;
  value: SmtpSettings | Record<string, unknown> | null;
}

const DEFAULTS: SmtpSettings = {
  host: "",
  port: 587,
  user: "",
  password: "",
  from: "",
  tls: true,
  ssl: false,
};

const SMTPSettingsTab: React.FC = () => {
  const toast = useToast();
  const [form, setForm] = useState<SmtpSettings>(DEFAULTS);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const response =
          await apiClient.get<SystemConfigRow[]>("/admin/system-config/");
        const smtp = response.data.find((c) => c.key === SMTP_CONFIG_KEY);
        if (smtp && smtp.value && typeof smtp.value === "object") {
          // V14.2.6: never populate the password field from the server response
          // (write-only field — existing value stays on the server).
          const settings = smtp.value as Partial<SmtpSettings>;
          const nonSecret = { ...settings };
          delete nonSecret.password;
          setForm({ ...DEFAULTS, ...nonSecret, password: "" });
        }
      } catch {
        toast.error("Could not load current SMTP settings.");
      } finally {
        setLoading(false);
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);

    // V01.3.3: Reject CR/LF injection and overly long values in string fields.
    for (const k of ["host", "user", "password", "from"] as const) {
      const v = form[k];
      if (typeof v === "string" && (v.length > 256 || /[\r\n]/.test(v))) {
        toast.error(`Invalid value in ${k} (too long or contains CR/LF).`);
        setSaving(false);
        return;
      }
    }

    // V12.3.1 / V02.2.3: Require exactly one transport-encryption flag to be set.
    if (!form.tls && !form.ssl) {
      toast.error("Enable STARTTLS or SSL — SCCAP refuses to send authenticated SMTP over cleartext.");
      setSaving(false);
      return;
    }
    if (form.tls && form.ssl) {
      toast.error("STARTTLS and SSL are mutually exclusive — enable only one.");
      setSaving(false);
      return;
    }

    // V14.2.6: Omit password from the PUT body when the field was left blank
    // (server retains the existing encrypted value).
    const { password, ...nonPasswordFields } = form;
    const valuePayload = password.length > 0
      ? form
      : nonPasswordFields;

    try {
      await apiClient.put(`/admin/system-config/${SMTP_CONFIG_KEY}`, {
        key: SMTP_CONFIG_KEY,
        value: valuePayload,
        description: "Dedicated SMTP Configuration",
        is_secret: true,
        encrypted: true, // V13.3.1 / V14.2.4: Fernet-encrypt at rest.
      });
      toast.success("SMTP configuration saved.");
    } catch {
      toast.error("Failed to save SMTP preferences.");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div
        className="sccap-card"
        style={{
          padding: 40,
          textAlign: "center",
          color: "var(--fg-muted)",
        }}
      >
        Loading SMTP settings…
      </div>
    );
  }

  const Field: React.FC<{
    label: string;
    hint?: string;
    children: React.ReactNode;
  }> = ({ label, hint, children }) => (
    <label style={{ display: "grid", gap: 6 }}>
      <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
        {label}
        {hint && (
          <span
            style={{
              marginLeft: 8,
              color: "var(--fg-subtle)",
              fontWeight: 400,
            }}
          >
            {hint}
          </span>
        )}
      </span>
      {children}
    </label>
  );

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>
          <Icon.Mail size={18} /> SMTP settings
        </h1>
        <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
          Outgoing mail server for password reset and user invitations.
        </div>
      </div>

      <form
        onSubmit={onSubmit}
        className="surface"
        style={{
          padding: 22,
          display: "grid",
          gap: 14,
          maxWidth: 640,
        }}
      >
        <Field label="SMTP host">
          <input
            className="sccap-input"
            placeholder="smtp.sendgrid.net"
            value={form.host}
            onChange={(e) => setForm({ ...form, host: e.target.value })}
            maxLength={256}
            required
          />
        </Field>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <Field label="Port">
            <input
              className="sccap-input"
              type="number"
              min={1}
              max={65535}
              value={form.port}
              onChange={(e) =>
                setForm({ ...form, port: Number(e.target.value) })
              }
              required
            />
          </Field>
          <Field label="Sender address" hint="(From)">
            <input
              className="sccap-input"
              type="email"
              placeholder="noreply@domain.com"
              value={form.from}
              onChange={(e) => setForm({ ...form, from: e.target.value })}
              maxLength={256}
              required
            />
          </Field>
        </div>

        <Field label="Username">
          <input
            className="sccap-input"
            placeholder="apikey or user@domain.com"
            value={form.user}
            onChange={(e) => setForm({ ...form, user: e.target.value })}
            maxLength={256}
            required
          />
        </Field>

        <Field label="Password" hint="(leave blank to keep existing)">
          <input
            className="sccap-input"
            type="password"
            placeholder="Enter new password / API key to update"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            maxLength={256}
          />
        </Field>

        <div
          style={{
            display: "flex",
            gap: 24,
            marginTop: 6,
            alignItems: "center",
          }}
        >
          {/* V12.3.1 / V02.2.3: Enforce mutual exclusion — turning one on turns the other off. */}
          <InlineToggle
            label="STARTTLS"
            value={form.tls}
            onChange={(v) => setForm({ ...form, tls: v, ssl: v ? false : form.ssl })}
          />
          <InlineToggle
            label="SSL"
            value={form.ssl}
            onChange={(v) => setForm({ ...form, ssl: v, tls: v ? false : form.tls })}
          />
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "flex-end",
            marginTop: 10,
          }}
        >
          <button
            type="submit"
            className="sccap-btn sccap-btn-primary"
            disabled={saving}
          >
            <Icon.Check size={13} /> {saving ? "Saving…" : "Save SMTP settings"}
          </button>
        </div>
      </form>
    </div>
  );
};

const InlineToggle: React.FC<{
  label: string;
  value: boolean;
  onChange: (v: boolean) => void;
}> = ({ label, value, onChange }) => (
  <label
    style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 10,
      fontSize: 13,
      color: "var(--fg)",
      cursor: "pointer",
    }}
  >
    <div
      className={`sccap-switch ${value ? "on" : ""}`}
      role="switch"
      aria-checked={value}
      tabIndex={0}
      onClick={() => onChange(!value)}
      onKeyDown={(e) => {
        if (e.key === " " || e.key === "Enter") {
          e.preventDefault();
          onChange(!value);
        }
      }}
    />
    {label}
  </label>
);

export default SMTPSettingsTab;
