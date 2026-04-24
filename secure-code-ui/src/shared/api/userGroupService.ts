// secure-code-ui/src/shared/api/userGroupService.ts
import apiClient from "./apiClient";

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
    const res = await apiClient.post<UserGroup>("/admin/user-groups", payload);
    return res.data;
  },

  update: async (id: string, payload: UserGroupUpdate): Promise<UserGroup> => {
    const res = await apiClient.patch<UserGroup>(
      `/admin/user-groups/${id}`,
      payload,
    );
    return res.data;
  },

  remove: async (id: string): Promise<void> => {
    await apiClient.delete(`/admin/user-groups/${id}`);
  },

  addMember: async (id: string, payload: MemberAdd): Promise<UserGroup> => {
    const res = await apiClient.post<UserGroup>(
      `/admin/user-groups/${id}/members`,
      payload,
    );
    return res.data;
  },

  removeMember: async (id: string, userId: number): Promise<void> => {
    await apiClient.delete(`/admin/user-groups/${id}/members/${userId}`);
  },
};
