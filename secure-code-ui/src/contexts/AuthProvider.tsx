// secure-code-ui/src/contexts/AuthProvider.tsx
import { AxiosError } from "axios";
import React, { useCallback, useEffect, useState, type ReactNode } from "react";
import apiClient from "../services/apiClient";
import {
  loginUser,
  logoutUser,
  registerUser,
} from "../services/authService";
import {
  type AuthContextType,
  type TokenResponse,
  type UserLoginData,
  type UserRead,
  type UserRegisterData,
} from "../types/api";
import { AuthContext } from "./AuthContext";

const ACCESS_TOKEN_KEY = "accessToken";

export const AuthProvider: React.FC<{ children: ReactNode }> = ({
  children,
}) => {
  const [user, setUser] = useState<UserRead | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(
    localStorage.getItem(ACCESS_TOKEN_KEY),
  );
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [initialAuthChecked, setInitialAuthChecked] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const clearError = useCallback(() => {
    setError(null);
  }, []);

  // Effect to synchronize the accessToken state with localStorage
  useEffect(() => {
    if (accessToken) {
      localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
    } else {
      localStorage.removeItem(ACCESS_TOKEN_KEY);
    }
  }, [accessToken]);

  const fetchAndSetUser = useCallback(async () => {
    if (!localStorage.getItem(ACCESS_TOKEN_KEY)) {
      setUser(null);
      return;
    }
    try {
      const response = await apiClient.get<UserRead>("/users/me");
      setUser(response.data);
    } catch (e) {
      console.error("AuthProvider: Failed to fetch user (token likely invalid/expired):", e);
      setUser(null);
      setAccessToken(null);
    }
  }, []);

  // Effect to run on initial load to check for an existing session
  useEffect(() => {
    const initializeAuth = async () => {
      setIsLoading(true);
      if (accessToken) {
        await fetchAndSetUser();
      }
      setInitialAuthChecked(true);
      setIsLoading(false);
    };
    initializeAuth();
  }, [accessToken, fetchAndSetUser]);

  const login = useCallback(async (credentials: UserLoginData) => {
    setIsLoading(true);
    setError(null);
    try {
      const response: TokenResponse = await loginUser(credentials);
      console.log("1. [AuthProvider] Token received from server:", response.access_token);
      console.log("2. [AuthProvider] Saving token to localStorage with key 'accessToken'");
      localStorage.setItem("accessToken", response.access_token);
      setAccessToken(response.access_token);
    } catch (err: unknown) {
      console.error("AuthProvider: Login failed:", err);
      let errorMessage = "Login failed. Please check your username and password.";
      if (err instanceof AxiosError && err.response?.data?.detail) {
        errorMessage = typeof err.response.data.detail === "string" ? err.response.data.detail : JSON.stringify(err.response.data.detail);
      }
      setError(errorMessage);
      setAccessToken(null);
      setUser(null);
      throw err;
    } finally {
      setIsLoading(false);
    }
  }, []);

  const register = useCallback(
    async (credentials: UserRegisterData): Promise<UserRead> => {
      setIsLoading(true);
      setError(null);
      try {
        return await registerUser(credentials);
      } catch (err: unknown) {
        console.error("AuthProvider: Registration failed:", err);
        let errorMessage = "Registration failed. Please try again.";
        if (err instanceof AxiosError && err.response?.data?.detail) {
          errorMessage = typeof err.response.data.detail === "string" ? err.response.data.detail : "An unexpected error occurred.";
        }
        setError(errorMessage);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  const logout = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      if (accessToken) {
        await logoutUser();
      }
    } catch (err: unknown) {
      console.error("AuthProvider: API Logout failed but proceeding with client-side logout:", err);
    } finally {
      setAccessToken(null);
      setUser(null);
      setIsLoading(false);
    }
  }, [accessToken]);

  const contextValue: AuthContextType = {
    user,
    accessToken,
    isLoading,
    initialAuthChecked,
    error,
    login,
    register,
    logout,
    clearError,
  };

  return (
    <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>
  );
};