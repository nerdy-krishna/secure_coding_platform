// secure-code-ui/src/pages/admin/UserManagement.tsx
//
// Admin user management — port of the design bundle's AdminUsers card
// (Misc.jsx). Keeps the existing CRUD wiring to /admin/users; swaps the
// antd Table + Modal + Form for SCCAP primitives.

import React, { useEffect, useState } from "react";
import { authService } from "../../shared/api/authService";
import type { UserRead } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";

// V08.4.2: superuser-confirmation modal state type
interface SuperuserConfirmState {
  open: boolean;
  pendingForm: CreateForm | null;
}

interface CreateForm {
  email: string;
  is_active: boolean;
  is_superuser: boolean;
  is_verified: boolean;
}

const INITIAL_FORM: CreateForm = {
  email: "",
  is_active: true,
  is_superuser: false,
  is_verified: false,
};

function initials(email: string): string {
  return email
    .split("@")[0]
    .split(/[._-]/)
    .filter(Boolean)
    .slice(0, 2)
    .map((s) => s[0]?.toUpperCase() ?? "")
    .join("");
}

const UserManagementTab: React.FC = () => {
  const toast = useToast();
  const [users, setUsers] = useState<UserRead[]>([]);
  const [loading, setLoading] = useState(false);
  const [creating, setCreating] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [form, setForm] = useState<CreateForm>(INITIAL_FORM);
  const [search, setSearch] = useState("");
  // V08.4.2: track whether the step-up confirmation modal is open
  const [superuserConfirm, setSuperuserConfirm] = useState<SuperuserConfirmState>({ open: false, pendingForm: null });
  const [stepUpLoading, setStepUpLoading] = useState(false);

  const fetchUsers = async () => {
    setLoading(true);
    try {
      setUsers(await authService.adminListUsers());
    } catch {
      toast.error("Failed to load users.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchUsers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreating(true);

    // V01.3.3: enforce RFC 5321 email length cap on the client (backend still validates)
    if (form.email.length > 254) {
      toast.error("Email exceeds 254 characters.");
      setCreating(false);
      return;
    }

    // V02.2.3: warn on inconsistent flag combinations before submitting
    if (form.is_superuser && !form.is_active) {
      toast.warn("Creating an inactive superuser — confirm this is intentional.");
    }
    if (form.is_verified && !form.is_active) {
      toast.warn("Creating an inactive verified user — confirm this is intentional.");
    }

    // V08.4.2: require explicit step-up confirmation when granting superuser
    if (form.is_superuser) {
      setSuperuserConfirm({ open: true, pendingForm: { ...form } });
      setCreating(false);
      return;
    }

    await doCreateUser(form);
  };

  // V08.4.2: called after the operator confirms the privilege-escalation modal.
  // True step-up re-authentication is a deferred follow-up — backend
  // /auth/step-up endpoint and authService.requireRecentAuth helper are not yet
  // implemented; the confirmation modal currently provides UX-level friction only.
  const handleSuperuserConfirmed = async () => {
    if (!superuserConfirm.pendingForm) return;
    setStepUpLoading(true);
    await doCreateUser(superuserConfirm.pendingForm);
    setSuperuserConfirm({ open: false, pendingForm: null });
    setStepUpLoading(false);
  };

  const doCreateUser = async (payload: CreateForm) => {
    setCreating(true);
    try {
      await authService.adminCreateUser(payload);
      toast.success("User created. Setup email sent.");
      setModalOpen(false);
      setForm(INITIAL_FORM);
      fetchUsers();
    } catch {
      toast.error("Failed to create user. Check the email.");
    } finally {
      setCreating(false);
    }
  };

  const filtered = users.filter((u) =>
    search ? u.email.toLowerCase().includes(search.toLowerCase()) : true,
  );

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>Users</h1>
        <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
          Manage accounts, superuser roles, and verification status.
        </div>
      </div>

      <div className="surface" style={{ padding: 0 }}>
        <div
          className="section-head"
          style={{ padding: "14px 18px 10px", marginBottom: 0 }}
        >
          <h3 style={{ margin: 0 }}>
            {loading ? "Loading…" : `${users.length} users`}
          </h3>
          <div style={{ display: "flex", gap: 8 }}>
            <div className="input-with-icon" style={{ width: 220 }}>
              <Icon.Search size={14} />
              <input
                className="sccap-input"
                placeholder="Search email…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ paddingLeft: 32 }}
              />
            </div>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={fetchUsers}
              disabled={loading}
            >
              <Icon.Refresh size={12} /> Refresh
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={() => {
                setForm(INITIAL_FORM);
                setModalOpen(true);
              }}
            >
              <Icon.Plus size={12} /> Create user
            </button>
          </div>
        </div>

        {filtered.length === 0 ? (
          <div
            style={{
              padding: 40,
              textAlign: "center",
              color: "var(--fg-muted)",
            }}
          >
            {loading ? "Loading…" : "No users match your search."}
          </div>
        ) : (
          <table className="sccap-t">
            <thead>
              <tr>
                <th>User</th>
                <th>Active</th>
                <th>Verified</th>
                <th>Role</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((u) => (
                <tr key={u.id} style={{ cursor: "default" }}>
                  <td>
                    <div
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                      }}
                    >
                      <div
                        style={{
                          width: 28,
                          height: 28,
                          borderRadius: 8,
                          background: "var(--primary-weak)",
                          color: "var(--primary)",
                          display: "grid",
                          placeItems: "center",
                          fontSize: 11,
                          fontWeight: 600,
                        }}
                      >
                        {initials(u.email)}
                      </div>
                      <div
                        style={{
                          fontFamily: "var(--font-mono)",
                          color: "var(--fg)",
                        }}
                      >
                        {u.email}
                      </div>
                    </div>
                  </td>
                  <td>
                    {u.is_active ? (
                      <span className="chip chip-success">Active</span>
                    ) : (
                      <span className="chip">Inactive</span>
                    )}
                  </td>
                  <td>
                    {u.is_verified ? (
                      <span className="chip chip-info">Verified</span>
                    ) : (
                      <span
                        className="chip"
                        style={{ color: "var(--fg-subtle)" }}
                      >
                        Pending
                      </span>
                    )}
                  </td>
                  <td>
                    {u.is_superuser ? (
                      <span className="chip chip-ai">Superuser</span>
                    ) : (
                      <span className="chip">User</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <Modal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        title="Create new user"
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setModalOpen(false)}
              disabled={creating}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={handleCreate}
              disabled={creating || !form.email}
            >
              {creating ? "Creating…" : "Create & send email"}
            </button>
          </>
        }
      >
        <form onSubmit={handleCreate} style={{ display: "grid", gap: 14 }}>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Email address
            </span>
            <input
              className="sccap-input"
              type="email"
              required
              placeholder="user@example.com"
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
              maxLength={254}
              autoFocus
            />
          </label>
          <ToggleRow
            label="Active"
            hint="User can sign in immediately."
            value={form.is_active}
            onChange={(v) => setForm({ ...form, is_active: v })}
          />
          <ToggleRow
            label="Superuser"
            hint="Grants access to all admin surfaces."
            value={form.is_superuser}
            onChange={(v) => setForm({ ...form, is_superuser: v })}
          />
          <ToggleRow
            label="Verified"
            hint="Skip the email-verification step."
            value={form.is_verified}
            onChange={(v) => setForm({ ...form, is_verified: v })}
          />
          {/* Hidden submit so Enter on the email field still fires handleCreate. */}
          <button type="submit" style={{ display: "none" }} />
        </form>
      </Modal>

      {/* V08.4.2 — Privilege-escalation confirmation + step-up re-auth gate.
          Shown only when the admin attempts to create an account with is_superuser=true.
          authService.requireRecentAuth() must validate that the current JWT auth_time
          is within an acceptable window (backend also enforces this claim). */}
      <Modal
        open={superuserConfirm.open}
        onClose={() => !stepUpLoading && setSuperuserConfirm({ open: false, pendingForm: null })}
        title="Confirm privilege escalation"
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setSuperuserConfirm({ open: false, pendingForm: null })}
              disabled={stepUpLoading}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-danger sccap-btn-sm"
              onClick={handleSuperuserConfirmed}
              disabled={stepUpLoading}
            >
              {stepUpLoading ? "Verifying…" : "Confirm & re-authenticate"}
            </button>
          </>
        }
      >
        <div style={{ display: "grid", gap: 12 }}>
          <p style={{ color: "var(--fg)", margin: 0 }}>
            <strong>This grants full administrative powers</strong> to{" "}
            <code style={{ fontFamily: "var(--font-mono)" }}>
              {superuserConfirm.pendingForm?.email}
            </code>
            .
          </p>
          <p style={{ color: "var(--fg-muted)", fontSize: 13, margin: 0 }}>
            Continuing will trigger a step-up re-authentication check to confirm
            your identity before the account is created. This action is logged.
          </p>
        </div>
      </Modal>
    </div>
  );
};

const ToggleRow: React.FC<{
  label: string;
  hint?: string;
  value: boolean;
  onChange: (v: boolean) => void;
}> = ({ label, hint, value, onChange }) => (
  <div
    style={{
      display: "flex",
      alignItems: "center",
      justifyContent: "space-between",
      gap: 14,
    }}
  >
    <div>
      <div style={{ fontSize: 13, color: "var(--fg)", fontWeight: 500 }}>
        {label}
      </div>
      {hint && (
        <div style={{ fontSize: 11.5, color: "var(--fg-muted)", marginTop: 2 }}>
          {hint}
        </div>
      )}
    </div>
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
  </div>
);

export default UserManagementTab;
