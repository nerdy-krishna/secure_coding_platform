import apiClient from "./apiClient";

export interface LogLevelResponse {
    level: string;
    message: string;
}

export interface LogService {
    getLogLevel: () => Promise<LogLevelResponse>;
    setLogLevel: (level: "DEBUG" | "INFO" | "WARNING" | "ERROR") => Promise<LogLevelResponse>;
}

export const logService: LogService = {
    getLogLevel: async () => {
        const response = await apiClient.get<LogLevelResponse>("/admin/logs/level");
        return response.data;
    },

    setLogLevel: async (level) => {
        const response = await apiClient.put<LogLevelResponse>("/admin/logs/level", {
            level,
        });
        return response.data;
    },
};
