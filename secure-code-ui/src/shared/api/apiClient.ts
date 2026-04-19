// secure-code-ui/src/shared/api/apiClient.ts
import axios from "axios";
import { authService } from "./authService";

// Get the API base URL from environment variables, fallback back to relative proxy path
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "/api/v1";
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true, // Let Axios handle the Content-Type header per request
});

// Request Interceptor
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("accessToken");
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  },
);
// Module-scoped dedup: if several requests hit 401 in parallel, only one
// /auth/refresh fires; the others await the same promise. Rotating refresh
// tokens invalidate the previous token, so concurrent refresh attempts would
// otherwise race and log the user out.
let refreshInFlight: Promise<string> | null = null;

function refreshAccessToken(): Promise<string> {
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = authService
    .refreshToken()
    .then(({ access_token }) => {
      localStorage.setItem("accessToken", access_token);
      apiClient.defaults.headers.common["Authorization"] = `Bearer ${access_token}`;
      return access_token;
    })
    .finally(() => {
      refreshInFlight = null;
    });
  return refreshInFlight;
}

// Response Interceptor
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // 401s trigger a single shared refresh attempt; skip the refresh endpoint
    // itself to prevent infinite loops.
    const isRefreshRequest = originalRequest.url?.includes("/auth/refresh");
    if (error.response?.status === 401 && !originalRequest._retry && !isRefreshRequest) {
      originalRequest._retry = true;

      try {
        const access_token = await refreshAccessToken();
        originalRequest.headers["Authorization"] = `Bearer ${access_token}`;
        return apiClient(originalRequest);
      } catch (refreshError) {
        console.error("Session refresh failed, logging out.", refreshError);
        localStorage.removeItem("accessToken");
        window.location.href = "/login";
        return Promise.reject(refreshError);
      }
    }

    return Promise.reject(error);
  },
);

export default apiClient;