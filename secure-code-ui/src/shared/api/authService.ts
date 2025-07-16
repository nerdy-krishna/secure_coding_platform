// secure-code-ui/src/shared/api/authService.ts
import apiClient from "../../shared/api/apiClient";
import {
  type TokenResponse,
  type UserLoginData,
  type UserRead,
  type UserRegisterData,
} from "../types/api";

export const authService = {
  // Login
  // FastAPI Users' /auth/login endpoint expects form data (username, password)
  // It returns an access_token and token_type.
  // The refresh token is set as an HttpOnly cookie.
  loginUser: async (
    loginData: UserLoginData,
  ): Promise<TokenResponse> => {
    const formData = new URLSearchParams();
    formData.append("username", loginData.username); // FastAPI Users uses 'username' which can be email
    formData.append("password", loginData.password);
    // Optional OAuth2 password flow parameters (usually not needed for simple user login)
    // if (loginData.grant_type) formData.append("grant_type", loginData.grant_type);
    // if (loginData.scope) formData.append("scope", loginData.scope);
    // if (loginData.client_id) formData.append("client_id", loginData.client_id);
    // if (loginData.client_secret) formData.append("client_secret", loginData.client_secret);
    const response = await apiClient.post("/auth/login", formData, {
      // CORRECTED PATH: relative to baseURL
      headers: {
        "Content-Type": "application/x-www-form-urlencoded", // Correct for this endpoint
      },
    });
    return response.data;
  },

  // Refresh Token
  refreshToken: async (): Promise<TokenResponse> => {
    // The refresh token is in an HttpOnly cookie, so the browser sends it automatically.
    // We just need to hit the refresh endpoint at the correct path.
    const response = await apiClient.post<TokenResponse>("/auth/jwt/refresh");
    return response.data;
  },

  // Register
  registerUser: async (
    registerData: UserRegisterData,
  ): Promise<UserRead> => {
    // FastAPI Users /auth/register endpoint expects JSON payload
    const response = await apiClient.post<UserRead>(
      "/auth/register", // CORRECT PATH: relative to baseURL
      registerData,
    );
    return response.data;
  },

  // Get Current User
  getCurrentUser: async (): Promise<UserRead> => {
    const response = await apiClient.get<UserRead>("/users/me");
    // CORRECT PATH: relative to baseURL
    return response.data;
  },
  // Logout
  logoutUser: async (): Promise<unknown> => {
    // FastAPI Users /auth/logout (or /auth/jwt/logout if JWT strategy specifically prefixes it,
    // but your docs suggest /auth/logout)
    const response = await apiClient.post("/auth/logout");
    // CORRECT PATH: relative to baseURL
    return response.data;
  },
};
