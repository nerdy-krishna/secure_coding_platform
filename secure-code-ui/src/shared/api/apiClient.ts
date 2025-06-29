// src/app/services/apiClient.ts
import axios from "axios";

// Get the API base URL from environment variables
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1";

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

// Response Interceptor (Your existing logic is good and can remain)
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      console.error(
        "Axios Interceptor: Saw a 401 Unauthorized error for URL:",
        error.config.url,
      );
      // The logic in AuthProvider is already handling the session cleanup
      // when it fails to fetch `/users/me`, so no immediate action is needed here.
      // This is good for logging or for more complex refresh token logic in the future.
    }
    return Promise.reject(error);
  },
);

export default apiClient;