// secure-code-ui/src/services/apiClient.ts
import axios from "axios";

// Get the API base URL from environment variables
// In a Vite app, environment variables prefixed with VITE_ are exposed to the client-side code.
// Make sure to create a .env file in your secure-code-ui/ directory with VITE_API_BASE_URL
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api/v1"; // Point 1

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json", // Point 2
  },
  withCredentials: true, // Point 3: Important for HttpOnly refresh cookies
});

// Request Interceptor
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("access_token"); // Point 4: CORRECTED KEY
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
  (error) => {
    // Point 5: Handle global errors, e.g., redirect to login if 401
    if (error.response && error.response.status === 401) {
      console.error(
        "Axios Interceptor: Authentication Error 401 on URL:",
        error.config.url,
        error.response.data,
      );
      // CAUTION: Globally redirecting here can be tricky and might interfere with AuthContext.
      // AuthContext already handles 401 on /users/me by clearing the session.
      // A global redirect here should be done carefully, e.g., by not acting on auth-related endpoints
      // or by triggering a logout action via an event/context if a more sophisticated flow is needed.

      // Example of a more careful redirect (if AuthContext wasn't already handling it on /users/me):
      // const originalRequestUrl = error.config.url;
      // const authEndpoints = ['/auth/jwt/login', '/auth/jwt/refresh', '/auth/register'];
      // if (!authEndpoints.some(endpoint => originalRequestUrl.includes(endpoint))) {
      //   localStorage.removeItem("access_token"); // Ensure consistency with AuthContext
      //   // Consider using a router navigation method if available outside a component,
      //   // or dispatching a global 'logout' event that AuthContext can listen to.
      //   // window.location.href = '/login'; // This is a hard redirect.
      // }
    }
    return Promise.reject(error);
  },
);

export default apiClient;
