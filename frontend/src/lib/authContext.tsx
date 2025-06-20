import React, { createContext, useState, useContext, useEffect, ReactNode, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import { api, LoginCredentials, RegisterData, TokenResponse } from './api';

// Token refresh interval (e.g., 14 minutes, to be safe before a 15-min expiry)
const TOKEN_REFRESH_INTERVAL = 14 * 60 * 1000;

// Define user roles to match backend UserRole enum
export enum UserRole {
  ADMIN = 'admin',
  TRADER = 'trader',
  VIEWER = 'viewer',
  API_USER = 'api_user'
}

// Define user type to match backend UserResponse model
export interface User {
  id: string;
  username: string;
  email: string;
  first_name: string | null;
  last_name: string | null;
  tenant_id: string;
  tenant_status: string;
  role: UserRole;
  is_active: boolean;
  is_verified: boolean;
  failed_login_attempts: number;
  locked_until: string | null;
  created_at: string;
}

// Define AuthState type - RESTORING token and refreshToken
interface AuthState {
  user: User | null;
  token: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

// Define the context interface
interface AuthContextType extends AuthState {
  login: (credentials: LoginCredentials) => Promise<boolean>;
  register: (userData: Omit<RegisterData, 'role'>) => Promise<boolean>;
  logout: (showToast?: boolean) => void;
  forgotPassword: (email: string) => Promise<boolean>;
  resetPassword: (data: { token: string; new_password: string; confirm_password: string }) => Promise<boolean>;
  handleOAuthCallback: (accessToken: string, refreshToken?: string) => Promise<void>;
  changePassword: (data: { current_password: string; new_password: string; }) => Promise<boolean>;
}

// Create context with default values
const AuthContext = createContext<AuthContextType>({
  user: null,
  token: null,
  refreshToken: null,
  isAuthenticated: false,
  isLoading: true,
  login: async () => false,
  register: async () => false,
  logout: () => {},
  forgotPassword: async () => false,
  resetPassword: async () => false,
  handleOAuthCallback: async () => { throw new Error('AuthContext not initialized'); },
  changePassword: async () => false,
});

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [state, setState] = useState<AuthState>({
    user: null,
    // Initialize from localStorage
    token: localStorage.getItem('access_token'),
    refreshToken: localStorage.getItem('refresh_token'),
    isAuthenticated: false,
    isLoading: true,
  });

  const navigate = useNavigate();

  const handleLogout = useCallback(async (showToast = true) => {
    try {
      if (state.token) {
        await api.logout();
      }
    } catch (error) {
      console.error('Logout API call failed, but logging out locally anyway.', error);
    } finally {
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      
      setState({
        user: null,
        token: null,
        refreshToken: null,
        isAuthenticated: false,
        isLoading: false,
      });
      
      navigate('/auth/login');
      if(showToast) toast.success('Logged out successfully');
    }
  }, [navigate, state.token]);

  // Store tokens and user data, updating the state
  const storeAuthData = useCallback(async (tokenResponse: TokenResponse): Promise<boolean> => {
    try {
      if (tokenResponse.access_token) {
        try {
          const [, payload] = tokenResponse.access_token.split('.');
          const { aud } = JSON.parse(atob(payload));
          if (aud === 'tradesage-api-gateway') {
            localStorage.setItem('access_token', tokenResponse.access_token);
          } else {
            console.warn(`Attempted to store token with incorrect audience ('${aud}') as access token. Aborting.`);
            return false; // Prevent storing bad token
          }
        } catch (e) {
          console.error("Failed to parse access token:", e);
          return false;
        }
      }

      if (tokenResponse.refresh_token) {
        localStorage.setItem('refresh_token', tokenResponse.refresh_token);
      }

      const user = await api.getCurrentUser();
      
      setState({
        user,
        token: tokenResponse.access_token,
        refreshToken: tokenResponse.refresh_token || state.refreshToken,
        isAuthenticated: true,
        isLoading: false,
      });
      
      return true;
    } catch (error) {
      console.error('Error storing auth data:', error);
      setState(prev => ({ ...prev, isLoading: false, isAuthenticated: false, user: null, token: null, refreshToken: null }));
      return false;
    }
  }, [state.refreshToken]);

  // Function to refresh the access token
  const refreshToken = useCallback(async (): Promise<boolean> => {
    console.log('Attempting to refresh token...');
    try {
      const tokenData = await api.refreshToken();
      await storeAuthData(tokenData);
      console.log('Token refreshed successfully.');
      return true;
    } catch (error) {
      console.error('Failed to refresh token:', error);
      handleLogout(false);
      toast.error('Your session has expired. Please log in again.');
      return false;
    }
  }, [handleLogout, storeAuthData]);

  // Load user data on initial load and set up token refresh
  useEffect(() => {
    let refreshInterval: NodeJS.Timeout;

    const loadUser = async () => {
      if (state.token) {
        try {
          const user = await api.getCurrentUser();
          setState(prevState => ({
            ...prevState,
            user,
            isAuthenticated: true,
            isLoading: false,
          }));

          refreshInterval = setInterval(refreshToken, TOKEN_REFRESH_INTERVAL);

        } catch (error) {
          console.error('Could not load user with existing token. Attempting refresh...', error);
          const refreshSuccess = await refreshToken();
          if (!refreshSuccess) {
            // refreshToken() already handles logout
          }
        }
      } else {
        setState(prevState => ({ ...prevState, isLoading: false }));
      }
    };

    loadUser();

    return () => clearInterval(refreshInterval);
  }, [state.token, refreshToken]); // Rely on state.token to trigger this effect

  const handleLogin = async (credentials: LoginCredentials): Promise<boolean> => {
    try {
      const data = await api.login(credentials);
      const success = await storeAuthData(data);
      
      if (success) {
        toast.success('Login successful!');
        navigate('/dashboard');
        return true;
      }
      return false;
    } catch (error: any) {
      console.error('Login error:', error);
      const errorMessage = error.detail || 'Login failed. Please check your credentials.';
      toast.error(errorMessage);
      return false;
    }
  };

  const handleOAuthCallback = async (accessToken: string, refreshToken?: string) => {
    try {
      // Guard: Validate the token from OAuth before processing
      try {
        const [, payload] = accessToken.split('.');
        const { aud } = JSON.parse(atob(payload));
        if (aud !== 'tradesage-api-gateway') {
          toast.error('Authentication failed: Invalid token received.');
          console.error(`OAuth callback received token with invalid audience: ${aud}`);
          navigate('/auth/login');
          return;
        }
      } catch (e) {
        toast.error('Authentication failed: Malformed token received.');
        console.error("Failed to parse token from OAuth callback:", e);
        navigate('/auth/login');
        return;
      }

      const tokenResponse: TokenResponse = { 
        access_token: accessToken, 
        refresh_token: refreshToken,
        token_type: 'bearer',
        expires_in: 3600, // This is a placeholder, the actual expiry is in the token
        tenant_status: 'active' // This should be updated based on user data if available
      };

      const success = await storeAuthData(tokenResponse);

      if (success) {
        navigate('/dashboard');
        toast.success('Successfully authenticated!');
      } else {
        // storeAuthData would have logged the reason
        toast.error('Failed to store authentication details.');
        navigate('/auth/login');
      }
    } catch (error) {
      console.error('OAuth callback error:', error);
      toast.error('Failed to process OAuth callback.');
      navigate('/auth/login');
    }
  };

  const handleRegister = async (userData: Omit<RegisterData, 'role'>): Promise<boolean> => { 
    try {
      const registrationData: RegisterData = { ...userData, role: UserRole.TRADER };
      const user = await api.register(registrationData);
      if (user) {
        toast.success('Registration successful! Please log in.');
        navigate('/auth/login');
        return true;
      }
      return false;
    } catch (error: any) {
      console.error('Registration error:', error);
      const errorMessage = error.detail || 'Registration failed. Please try again.';
      toast.error(errorMessage);
      return false;
    }
  };

  const handleForgotPassword = async (email: string): Promise<boolean> => {
    try {
      await api.requestPasswordReset(email);
      toast.success('If an account exists, password reset instructions have been sent.');
      return true;
    } catch (error: any) {
      console.error('Forgot password error:', error);
      toast.error(error.detail || 'An error occurred.');
      return false;
    }
  };

  const handleResetPassword = async (data: { token: string; new_password: string; confirm_password: string }): Promise<boolean> => {
    try {
      if (data.new_password !== data.confirm_password) {
        toast.error('Passwords do not match');
        return false;
      }
      await api.confirmPasswordReset(data);
      toast.success('Password reset successful. Please log in.');
      navigate('/auth/login');
      return true;
    } catch (error: any) {
      console.error('Reset password error:', error);
      const errorMessage = error.detail || 'Failed to reset password.';
      toast.error(errorMessage);
      return false;
    }
  };

  const handleChangePassword = async (data: { current_password: string; new_password: string; }): Promise<boolean> => {
    try {
      await api.changePassword(data);
      toast.success('Password changed successfully!');
      return true;
    } catch (error: any) {
      console.error('Change password error:', error);
      const errorMessage = error.detail || 'Failed to change password.';
      toast.error(errorMessage);
      return false;
    }
  };

  const contextValue = {
    ...state,
    login: handleLogin,
    register: handleRegister,
    logout: handleLogout,
    forgotPassword: handleForgotPassword,
    resetPassword: handleResetPassword,
    handleOAuthCallback,
    changePassword: handleChangePassword,
  };

  return <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  return useContext(AuthContext);
};
