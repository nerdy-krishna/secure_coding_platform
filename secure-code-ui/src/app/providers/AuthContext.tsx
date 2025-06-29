// src/app/contexts/AuthContext.tsx
import { createContext } from "react";
import {
  type UserLoginData,
  type UserRead,
  type UserRegisterData,
} from "../../shared/types/api";
export interface AuthContextType {
  user: UserRead | null;
  accessToken: string | null;
  isLoading: boolean;
  initialAuthChecked: boolean;
  error: string | null;
  login: (credentials: UserLoginData) => Promise<void>;
  register: (credentials: UserRegisterData) => Promise<UserRead>;
  logout: () => Promise<void>;
  clearError: () => void;
}

export const AuthContext = createContext<AuthContextType | undefined>(
  undefined,
);
