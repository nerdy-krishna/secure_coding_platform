import apiClient from "./apiClient";

export interface SystemConfiguration {
    key: string;
    value: any;
    description?: string;
    is_secret: boolean;
    encrypted: boolean;
}

export interface SystemConfigurationUpdate {
    value?: any;
    description?: string;
    is_secret?: boolean;
    encrypted?: boolean;
}

export const systemConfigService = {
    getAll: async (): Promise<SystemConfiguration[]> => {
        const response = await apiClient.get<SystemConfiguration[]>("/admin/system-config/");
        return response.data;
    },

    getByKey: async (key: string): Promise<SystemConfiguration> => {
        // Since getByKey is not exposed as a direct endpoint in the router (only getAll and Update/Delete),
        // we might filter from getAll or add a specific endpoint.
        // However, looking at admin_config.py, it only has getAll, update, delete.
        // Let's implement getByKey by filtering getAll for now, or assume we fetch all.
        // Actually, for settings page, we likely only need update.
        // But wait, we need to show current value.
        // Let's rely on getAll and find the key.
        const all = await systemConfigService.getAll();
        const found = all.find(c => c.key === key);
        if (!found) {
            throw new Error(`Configuration key ${key} not found`);
        }
        return found;
    },

    update: async (key: string, data: SystemConfigurationUpdate): Promise<SystemConfiguration> => {
        const response = await apiClient.put<SystemConfiguration>(`/admin/system-config/${key}`, data);
        return response.data;
    },
    
    delete: async (key: string): Promise<void> => {
        await apiClient.delete(`/admin/system-config/${key}`);
    }
};
