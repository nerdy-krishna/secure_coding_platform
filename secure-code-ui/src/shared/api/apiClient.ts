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
// Response Interceptor
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Check if the error is 401 and it's not a retry request
    // Also skip interception for the refresh endpoint itself to prevent infinite loops
    const isRefreshRequest = originalRequest.url?.includes("/auth/refresh");
    if (error.response?.status === 401 && !originalRequest._retry && !isRefreshRequest) {
      originalRequest._retry = true; // Mark it as a retry to prevent infinite loops

      try {
        // Attempt to refresh the token
        const tokenResponse = await authService.refreshToken();
        const { access_token } = tokenResponse;

        // Store the new token
        localStorage.setItem("accessToken", access_token);

        // Update the Authorization header for the original request and for all future requests
        apiClient.defaults.headers.common["Authorization"] = `Bearer ${access_token}`;
        originalRequest.headers["Authorization"] = `Bearer ${access_token}`;

        // Retry the original request with the new token
        return apiClient(originalRequest);
      } catch (refreshError) {
        // If the refresh token is also invalid, log the user out
        console.error("Session refresh failed, logging out.", refreshError);
        localStorage.removeItem("accessToken");
        window.location.href = "/login";
        return Promise.reject(refreshError);
      }
    }

    // For all other errors, just pass them along
    return Promise.reject(error);
  },
);

export default apiClient;