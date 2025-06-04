// secure-code-ui/src/hooks/useAuth.ts
import { useContext } from "react";
// Ensure this path correctly points to the file from Step 1
import { AuthContext, type AuthContextType } from "../contexts/AuthContext"; // Correct relative path

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
