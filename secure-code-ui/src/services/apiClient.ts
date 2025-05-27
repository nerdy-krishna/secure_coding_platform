// secure-code-ui/src/services/apiClient.ts
import axios from 'axios';

// Get the API base URL from environment variables
// In a Vite app, environment variables prefixed with VITE_ are exposed to the client-side code.
// Make sure to create a .env file in your secure-code-ui/ directory with VITE_API_BASE_URL
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  // withCredentials: true, // Important for cookies if your API is on a different domain during development
});

// You can add interceptors here for handling tokens or errors globally
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('authToken'); // Or however you store your access token
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    // Handle global errors, e.g., redirect to login if 401
    if (error.response && error.response.status === 401) {
      // Example: clear token and redirect
      // localStorage.removeItem('authToken');
      // window.location.href = '/login';
      console.error('Authentication Error:', error.response.data);
    }
    return Promise.reject(error);
  }
);

export default apiClient;