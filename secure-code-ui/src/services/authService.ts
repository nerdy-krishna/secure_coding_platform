// secure-code-ui/src/services/authService.ts
import apiClient from './apiClient';
import { type UserLoginData, type UserRegisterData, type TokenResponse, type UserRead } from '../types/api'; // We'll define these types next

// Login
// FastAPI Users' /jwt/login endpoint expects form data (username, password)
// It returns an access_token and token_type. The refresh token is set as an HttpOnly cookie.
export const loginUser = async (loginData: UserLoginData): Promise<TokenResponse> => {
  // Convert JSON to URL-encoded form data
  const formData = new URLSearchParams();
  formData.append('username', loginData.username); // FastAPI Users uses 'username' for email here
  formData.append('password', loginData.password);
  if (loginData.grant_type) formData.append('grant_type', loginData.grant_type);
  if (loginData.scope) formData.append('scope', loginData.scope);
  if (loginData.client_id) formData.append('client_id', loginData.client_id);
  if (loginData.client_secret) formData.append('client_secret', loginData.client_secret);

  const response = await apiClient.post('/auth/login', formData, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  });
  return response.data;
};

// Register
export const registerUser = async (registerData: UserRegisterData): Promise<UserRead> => { // Assuming UserRead is the response type upon successful registration
  const response = await apiClient.post<UserRead>('/auth/register', registerData);
  return response.data;
};

// Get Current User (example)
export const getCurrentUser = async (): Promise<UserRead> => {
  const response = await apiClient.get<UserRead>('/users/me');
  return response.data;
}