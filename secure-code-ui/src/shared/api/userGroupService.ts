// secure-code-ui/src/shared/api/userGroupService.ts
//
// DANGEROUS FUNCTIONALITY (V15.1.5): writes here mutate the H.2
// visibility scope (visible_user_ids). Adding a member to the wrong
// group or upgrading their role to "owner" widens the cross-tenant view
// for every subsequent list endpoint. Admin UI MUST confirm before each
// addMember / role change and ideally render the resulting effective
// scope before saving.
import apiClient from "./apiClient";

// Input validation patterns (V02.2.1)
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

// Allowed role values (V15.3.5)
const ALLOWED_ROLES = new Set(["member", "owner"] as const);

// In-flight guard: prevents more than 5 concurrent addMember calls (V02.3.2 / V02.4.1)
let _addMemberPending = 0;

export interface UserGroupMember {
  user_id: number;
  email: string;
  role: string;
}

export interface UserGroup {
  id: string;
  name: string;
  description: string | null;
  created_by: number;
  member_count: number;
  members: UserGroupMember[];
}

export interface UserGroupCreate {
  name: string;
  description?: string | null;
}

export interface UserGroupUpdate {
  name?: string;
  description?: string | null;
}

/**
 * `role` must be `"member"` or `"owner"` and is enforced by the backend
 * Pydantic schema (V02.1.1). Any other value is rejected client-side before
 * the request leaves the browser.
 */
export interface MemberAdd {
  email: string;
  role?: "member" | "owner";
}

export const userGroupService = {
  list: async (): Promise<UserGroup[]> => {
    const res = await apiClient.get<UserGroup[]>("/admin/user-groups");
    return res.data;
  },

  create: async (payload: UserGroupCreate): Promise<UserGroup> => {
    // V15.3.3: forward only the explicitly allowed fields
    if (
      payload.name !== undefined &&
      (payload.name.length === 0 || payload.name.length > 100)
    ) {
      throw new Error("name must be between 1 and 100 characters");
    }
    if (
      payload.description !== undefined &&
      payload.description !== null &&
      payload.description.length > 1000
    ) {
      throw new Error("description must not exceed 1000 characters");
    }
    const safePayload: UserGroupCreate = {
      name: payload.name,
      description: payload.description ?? null,
    };
    const res = await apiClient.post<UserGroup>(
      "/admin/user-groups",
      safePayload,
    );
    return res.data;
  },

  update: async (id: string, payload: UserGroupUpdate): Promise<UserGroup> => {
    // V02.2.1: validate UUID shape
    if (!UUID_RE.test(id)) {
      throw new Error("invalid group id");
    }
    if (
      payload.name !== undefined &&
      (payload.name.length === 0 || payload.name.length > 100)
    ) {
      throw new Error("name must be between 1 and 100 characters");
    }
    if (
      payload.description !== undefined &&
      payload.description !== null &&
      payload.description.length > 1000
    ) {
      throw new Error("description must not exceed 1000 characters");
    }
    // V15.3.3: forward only the explicitly allowed fields
    const safePayload: UserGroupUpdate = {
      name: payload.name,
      description: payload.description ?? null,
    };
    const res = await apiClient.patch<UserGroup>(
      // V01.2.2: encode path segment
      `/admin/user-groups/${encodeURIComponent(id)}`,
      safePayload,
    );
    return res.data;
  },

  remove: async (id: string): Promise<void> => {
    // V02.2.1: validate UUID shape
    if (!UUID_RE.test(id)) {
      throw new Error("invalid group id");
    }
    // V01.2.2: encode path segment
    await apiClient.delete(`/admin/user-groups/${encodeURIComponent(id)}`);
  },

  /**
   * WARNING (V15.1.5): adding a member to a group widens the H.2 cross-tenant
   * visibility scope for every list endpoint. Confirm the intended group and
   * the resulting effective scope before calling this method.
   *
   * Backend rate-limiting enforces server-side caps; client-side guard below
   * prevents accidental loops from firing unbounded concurrent requests
   * (V02.3.2 / V02.4.1).
   */
  addMember: async (id: string, payload: MemberAdd): Promise<UserGroup> => {
    // V02.2.1: validate UUID shape
    if (!UUID_RE.test(id)) {
      throw new Error("invalid group id");
    }
    // V02.2.1: validate email
    if (!EMAIL_RE.test(payload.email)) {
      throw new Error("invalid email address");
    }
    if (payload.email.length > 254) {
      throw new Error("email must not exceed 254 characters");
    }
    // V02.1.1 / V15.3.5: enforce role allow-list at runtime
    if (payload.role && !ALLOWED_ROLES.has(payload.role)) {
      throw new Error("invalid role");
    }
    // V02.3.2 / V02.4.1: in-flight concurrency guard
    if (_addMemberPending > 5) {
      throw new Error("too many concurrent member additions");
    }
    // V15.3.3: build an explicit safe payload — narrows role and prevents
    // privilege-elevation strings reaching the backend. Backend authorization
    // remains authoritative per V15.3.3.
    const safePayload: MemberAdd = {
      email: payload.email,
      role: payload.role === "owner" ? "owner" : "member",
    };
    _addMemberPending++;
    try {
      // V01.2.2: encode path segment
      const res = await apiClient.post<UserGroup>(
        `/admin/user-groups/${encodeURIComponent(id)}/members`,
        safePayload,
      );
      return res.data;
    } finally {
      _addMemberPending--;
    }
  },

  removeMember: async (id: string, userId: number): Promise<void> => {
    // V02.2.1: validate UUID shape
    if (!UUID_RE.test(id)) {
      throw new Error("invalid group id");
    }
    // V01.2.2: encode both path segments
    await apiClient.delete(
      `/admin/user-groups/${encodeURIComponent(id)}/members/${encodeURIComponent(String(userId))}`,
    );
  },
};
