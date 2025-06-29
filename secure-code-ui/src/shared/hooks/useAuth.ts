// src/app/hooks/useAuth.ts
import { useContext } from "react";
import { AuthContext, type AuthContextType } from "../../app/providers//AuthContext";

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
