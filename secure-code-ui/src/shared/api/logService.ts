// secure-code-ui/src/shared/api/logService.ts
//
// DANGEROUS FUNCTIONALITY (V15.1.5): setLogLevel mutates the global runtime
// log level for the entire backend. Setting DEBUG can leak PII, tokens, and
// LLM payloads to Loki; the endpoint is superuser-only and audited server-
// side. UI must confirm with the operator before invoking with "DEBUG".

import apiClient from "./apiClient";

interface LogLevelResponse {
    level: string;
    message: string;
}

interface LogService {
    getLogLevel: () => Promise<LogLevelResponse>;
    setLogLevel: (level: "DEBUG" | "INFO" | "WARNING" | "ERROR") => Promise<LogLevelResponse>;
}

export const logService: LogService = {
    getLogLevel: async () => {
        const response = await apiClient.get<LogLevelResponse>("/admin/logs/level");
        return response.data;
    },

    /**
     * DANGEROUS (V15.1.5): Mutates the global runtime log level for the entire
     * backend. Setting "DEBUG" can leak PII, tokens, and LLM payloads to Loki.
     * This endpoint is superuser-only and audited server-side.
     * Always confirm with the operator before invoking with "DEBUG".
     */
    setLogLevel: async (level) => {
        // V02.2.1: Enforce the allow-list at runtime; TypeScript types alone are
        // insufficient when callers bypass type-checking or pass dynamic strings.
        const ALLOWED = ["DEBUG", "INFO", "WARNING", "ERROR"] as const;
        if (!(ALLOWED as readonly string[]).includes(level)) {
            throw new Error("Invalid log level");
        }
        const response = await apiClient.put<LogLevelResponse>("/admin/logs/level", {
            level,
        });
        return response.data;
    },
};
