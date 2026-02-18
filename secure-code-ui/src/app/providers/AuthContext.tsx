// secure-code-ui/src/app/providers/AuthContext.tsx
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
  isSetupCompleted: boolean;
  checkSetupStatus: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextType | undefined>(
  undefined,
);
