// secure-code-ui/src/types/api.ts

// For Login
export interface UserLoginData { // Make sure 'export' is here
  username: string; // This will be the email
  password: string;
  grant_type?: string; // Optional, usually 'password'
  scope?: string;      // Optional
  client_id?: string;  // Optional
  client_secret?: string; // Optional
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

// For Registration (matches FastAPI Users UserCreate schema)
export interface UserRegisterData {
  email: string;
  password: string;
  is_active?: boolean;
  is_superuser?: boolean;
  is_verified?: boolean;
}

// For User Read (matches FastAPI Users UserRead schema)
export interface UserRead {
  id: string;
  email: string;
  is_active: boolean;
  is_superuser: boolean;
  is_verified: boolean;
}