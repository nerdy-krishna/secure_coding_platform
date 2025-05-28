// secure-code-ui/src/contexts/AuthProvider.tsx
import { AxiosError } from "axios";
import React, { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  getCurrentUser,
  loginUser,
  logoutUser,
  registerUser,
} from "../services/authService";
import {
  type TokenResponse,
  type UserLoginData,
  type UserRead,
  type UserRegisterData,
} from "../types/api";
import { AuthContext, type AuthContextType } from "./AuthContext"; // Imports from the context definition file

const ACCESS_TOKEN_KEY = "access_token";

export const AuthProvider: React.FC<{ children: ReactNode }> = ({
  children,
}) => {
  const [user, setUser] = useState<UserRead | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true); // True during initial auth check and auth operations
  const [initialAuthChecked, setInitialAuthChecked] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const clearError = useCallback(() => {
    // console.log('AuthProvider: clearError called');
    setError(null);
  }, []);

  const fetchAndSetUser = useCallback(async () => {
    // This function assumes a token might be available for the apiClient to use (e.g., via interceptor or already set in state)
    // It tries to fetch the current user. If it fails, it means the current session/token is invalid.
    try {
      const currentUser = await getCurrentUser();
      setUser(currentUser);
      // If successful, any existing error related to fetching user should be cleared (though not explicitly set here)
      // Consider if clearError() should be called here on success if there's a scenario it's needed.
    } catch (e) {
      console.error(
        "AuthProvider: Failed to fetch user (token likely invalid/expired):",
        e,
      );
      setUser(null);
      // CRITICAL FIX: If we can't fetch user, the current accessToken is bad. Clear it.
      localStorage.removeItem(ACCESS_TOKEN_KEY);
      setAccessToken(null);
    }
  }, []);

  useEffect(() => {
    const initializeAuth = async () => {
      setIsLoading(true);
      try {
        const storedToken = localStorage.getItem(ACCESS_TOKEN_KEY);
        if (storedToken) {
          setAccessToken(storedToken); // Optimistically set token for apiClient to use
          await fetchAndSetUser(); // Verify token by fetching user. Clears token if fetch fails.
        }
      } catch (e) {
        // This catch is for unexpected errors during localStorage access or initial state setting
        console.error("AuthProvider: Initialization error:", e);
        localStorage.removeItem(ACCESS_TOKEN_KEY); // Ensure cleanup
        setAccessToken(null);
        setUser(null);
      } finally {
        setIsLoading(false);
        setInitialAuthChecked(true);
      }
    };
    initializeAuth();
  }, [fetchAndSetUser]);

  const login = useCallback(
    async (credentials: UserLoginData) => {
      setIsLoading(true);
      setError(null);
      try {
        const response: TokenResponse = await loginUser(credentials);
        localStorage.setItem(ACCESS_TOKEN_KEY, response.access_token);
        setAccessToken(response.access_token);
        await fetchAndSetUser(); // Fetch user details with the new token
      } catch (err: unknown) {
        console.error("AuthProvider: Login failed:", err);
        let errorMessage = "Login failed. Please try again.";
        if (err instanceof AxiosError && err.response?.data?.detail) {
          errorMessage =
            typeof err.response.data.detail === "string"
              ? err.response.data.detail
              : JSON.stringify(err.response.data.detail);
        } else if (err instanceof Error) {
          errorMessage = err.message;
        }
        setError(errorMessage);
        // console.log('AuthProvider: setError called in login with:', errorMessage);
        localStorage.removeItem(ACCESS_TOKEN_KEY); // Clean up on failed login
        setAccessToken(null);
        setUser(null);
        throw err; // Re-throw for component-level error handling if needed
      } finally {
        setIsLoading(false);
      }
    },
    [fetchAndSetUser],
  );

  const register = useCallback(
    async (credentials: UserRegisterData): Promise<UserRead> => {
      setIsLoading(true);
      setError(null);
      try {
        const registeredUser = await registerUser(credentials);
        // Does not log in the user automatically, just returns registration status/data
        return registeredUser;
      } catch (err: unknown) {
        console.error("AuthProvider: Registration failed:", err);
        let errorMessage = "Registration failed. Please try again.";
        if (err instanceof AxiosError && err.response?.data?.detail) {
          if (typeof err.response.data.detail === "string") {
            errorMessage = err.response.data.detail;
          } else if (
            Array.isArray(err.response.data.detail) &&
            err.response.data.detail.length > 0
          ) {
            errorMessage = err.response.data.detail
              .map(
                (e: { msg: string; loc: (string | number)[] }) =>
                  `${e.loc.join(".")}: ${e.msg}`,
              )
              .join("; ");
          } else {
            errorMessage = JSON.stringify(err.response.data.detail);
          }
        } else if (err instanceof Error) {
          errorMessage = err.message;
        }
        setError(errorMessage);
        // console.log('AuthProvider: setError called in register with:', errorMessage);
        throw err;
      } finally {
        setIsLoading(false);
      }
    },
    [],
  );

  const logout = useCallback(async () => {
    setIsLoading(true);
    setError(null); // Clear any errors on logout
    try {
      if (accessToken) {
        // Only call API if there was a token
        await logoutUser(); // Call backend logout
      }
    } catch (err: unknown) {
      console.error("AuthProvider: API Logout failed:", err);
      // Don't necessarily set an error here, as client-side logout will proceed
    } finally {
      localStorage.removeItem(ACCESS_TOKEN_KEY);
      setAccessToken(null);
      setUser(null);
      // Any interceptor relying on token should now fail or not add auth header
      setIsLoading(false);
      console.log("AuthProvider: User logged out, token cleared.");
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
