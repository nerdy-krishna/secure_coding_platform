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
    try {
      await authService.adminCreateUser(form);
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
        <h1 style={{ color: "var(--fg)" }}>
          <Icon.Users size={18} /> Users
        </h1>
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
