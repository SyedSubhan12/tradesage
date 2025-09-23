import axios, { AxiosError, AxiosRequestConfig, AxiosHeaders } from 'axios';
import { toast } from 'react-toastify';
import { User, UserRole } from './authContext';

const API_BASE_URL = '/api'; // Use relative URLs to work with Vite proxy

// Lightweight conditional logger for development
const isDev = import.meta.env.MODE !== 'production';
const debugLog = (...args: unknown[]) => {
  if (isDev) {
    console.debug(...args);
  }
};

// Token storage abstraction
const tokenStorage = {
  getAccessToken: () => localStorage.getItem('access_token'),
  setAccessToken: (token: string) => localStorage.setItem('access_token', token),
  getRefreshToken: () => localStorage.getItem('refresh_token'),
  setRefreshToken: (token: string) => localStorage.setItem('refresh_token', token),
  clearTokens: () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
  },
};

// Create axios instance
const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000, // Global 10-second timeout
});

// Enhanced refresh token management with exponential backoff
interface RefreshTokenState {
  promise: Promise<string | null> | null;
  attempts: number;
  lastAttempt: number;
  maxAttempts: number;
}

const refreshTokenState: RefreshTokenState = {
  promise: null,
  attempts: 0,
  lastAttempt: 0,
  maxAttempts: 3,
};

// Enhanced token validation
const isTokenValid = (token: string | null): boolean => {
  if (!token) return false;
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    const exp = payload.exp * 1000; // Convert to milliseconds
    const now = Date.now();
    return exp > now + 300_000; // 5-minute buffer
  } catch (error) {
    console.error('Invalid token format:', error);
    return false;
  }
};

// Refresh access token with backoff and validation
const refreshAccessToken = async (): Promise<TokenResponse> => {
  const refreshToken = tokenStorage.getRefreshToken();
  if (!refreshToken) {
    throw new Error('No refresh token available');
  }

  if (!isTokenValid(refreshToken)) {
    console.error('Refresh token is expired or invalid');
    tokenStorage.clearTokens();
    throw new Error('Refresh token is invalid');
  }

  const baseDelay = 1000; // 1 second
  const backoffDelay = Math.min(baseDelay * Math.pow(2, refreshTokenState.attempts), 30000); // Max 30 seconds

  if (refreshTokenState.attempts > 0) {
    const timeSinceLastAttempt = Date.now() - refreshTokenState.lastAttempt;
    if (timeSinceLastAttempt < backoffDelay) {
      const waitTime = backoffDelay - timeSinceLastAttempt;
      debugLog(`Applying exponential backoff: waiting ${waitTime}ms before retry`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }
  }

  refreshTokenState.lastAttempt = Date.now();
  refreshTokenState.attempts++;

  try {
    debugLog(`🚀 Attempting token refresh (attempt ${refreshTokenState.attempts}/${refreshTokenState.maxAttempts})`);
    const response = await axiosInstance.post<TokenResponse>(
      '/auth/refresh',
      {},
      {
        headers: { Authorization: `Bearer ${refreshToken}` },
        timeout: 10000,
      }
    );

    refreshTokenState.attempts = 0;
    refreshTokenState.lastAttempt = 0;

    if (!isTokenValid(response.data.access_token)) {
      throw new Error('Received invalid access token');
    }

    tokenStorage.setAccessToken(response.data.access_token);
    if (response.data.refresh_token) {
      tokenStorage.setRefreshToken(response.data.refresh_token);
      debugLog("🔄 New refresh token received - 30-day renewal cycle activated");
    } else {
      debugLog("  Using existing refresh token (still valid for current 30-day cycle)");
    }

    return response.data;
  } catch (error) {
    console.error(`Token refresh failed (attempt ${refreshTokenState.attempts}):`, error);
    if (refreshTokenState.attempts >= refreshTokenState.maxAttempts) {
      console.error('Max refresh attempts reached. Clearing tokens.');
      tokenStorage.clearTokens();
      refreshTokenState.attempts = 0;
      refreshTokenState.lastAttempt = 0;
      throw new Error('Max refresh attempts exceeded');
    }
    throw error;
  }
};

// Request interceptor
axiosInstance.interceptors.request.use(
  (config) => {
    if (config.url?.endsWith('/auth/refresh')) {
      return config;
    }

    const token = tokenStorage.getAccessToken();
    if (token && !config.headers?.has('Authorization')) {
      config.headers = new AxiosHeaders({
        ...config.headers,
        Authorization: `Bearer ${token}`,
      });
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor with retry logic
axiosInstance.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };
    if (error.response?.status !== 401 || !originalRequest) {
      if (error.response?.status === 403) {
        console.error('Access forbidden. User may not have proper permissions.');
      } else if (error.response?.status === 429) {
        console.warn('Rate limit exceeded. Retrying after delay.');
        await new Promise(resolve => setTimeout(resolve, 1000));
        return axiosInstance(originalRequest);
      }
      return Promise.reject(error.response?.data || { message: 'Unknown error' });
    }

    if (originalRequest.url?.endsWith('/auth/refresh')) {
      console.error('Refresh token invalid or expired. Clearing tokens.');
      tokenStorage.clearTokens();
      refreshTokenState.promise = null;
      refreshTokenState.attempts = 0;
      refreshTokenState.lastAttempt = 0;
      if (typeof window !== 'undefined') {
        window.location.href = '/auth/login';
      }
      return Promise.reject(error);
    }

    if (originalRequest._retry) {
      console.error('Request already retried. Rejecting.');
      return Promise.reject(error);
    }

    originalRequest._retry = true;

    if (!refreshTokenState.promise) {
      debugLog('Starting new token refresh operation');
      refreshTokenState.promise = new Promise(async (resolve, reject) => {
        try {
          const tokenResponse = await refreshAccessToken();
          const newAccessToken = tokenResponse.access_token;
          tokenStorage.setAccessToken(newAccessToken);
          if (tokenResponse.refresh_token) {
            tokenStorage.setRefreshToken(tokenResponse.refresh_token);
            debugLog("🔄 New refresh token received - 30-day renewal cycle activated");
          }
          debugLog('Token refresh operation completed successfully');
          resolve(newAccessToken);
        } catch (refreshError) {
          console.error('Token refresh operation failed:', refreshError);
          tokenStorage.clearTokens();
          if (typeof window !== 'undefined') {
            window.location.href = '/auth/login';
          }
          reject(refreshError);
        } finally {
          refreshTokenState.promise = null;
        }
      });
    } else {
      debugLog('Token refresh already in progress. Waiting for completion.');
    }

    try {
      const newToken = await refreshTokenState.promise;
      if (newToken && originalRequest.headers) {
        originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
        debugLog('Retrying original request with new token');
        return axiosInstance(originalRequest);
      }
      return Promise.reject(new Error('Token refresh completed but no valid token received'));
    } catch (refreshError) {
      console.error('Failed to wait for token refresh:', refreshError);
      return Promise.reject(refreshError);
    }
  }
);

// Types
export interface LoginCredentials {
  username: string;
  password: string;
}

export interface RegisterData {
  username: string;
  email: string;
  password: string;
  first_name?: string;
  last_name?: string;
  role?: UserRole;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  tenant_status: string;
}

// Auth API calls
export const api = {
  register: async (userData: RegisterData): Promise<User> => {
    const response = await axiosInstance.post<User>('/users/register', userData);
    return response.data;
  },

  login: async (credentials: LoginCredentials): Promise<TokenResponse> => {
    const formData = new URLSearchParams();
    formData.append('username', credentials.username);
    formData.append('password', credentials.password);
    formData.append('grant_type', 'password');
    const response = await axiosInstance.post<TokenResponse>('/auth/token', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    return response.data;
  },

  logout: async (): Promise<{ refresh_token_deletion_result?: boolean; refresh_token_deletion_reason?: string; logout?: boolean; authenticated?: boolean }> => {
    const token = tokenStorage.getAccessToken();
    const refreshToken = tokenStorage.getRefreshToken();
    try {
      if (refreshToken && !isTokenValid(refreshToken)) {
        debugLog('Refresh token invalid during logout. Clearing tokens.');
        tokenStorage.clearTokens();
        return { logout: true };
      }
      const response = await axiosInstance.post(
        '/auth/logout',
        {},
        { headers: token ? { Authorization: `Bearer ${token}` } : {} }
      );
      tokenStorage.clearTokens();
      if (response.data?.refresh_token_deletion_result === false) {
        debugLog('Logout: Refresh token deletion not successful', {
          reason: response.data.refresh_token_deletion_reason || 'unknown',
        });
      }
      return response.data || { logout: true };
    } catch (error: any) {
      debugLog('Logout error:', error);
      tokenStorage.clearTokens();
      return error.response?.data || { logout: false, refresh_token_deletion_result: false, refresh_token_deletion_reason: 'exception' };
    }
  },

  getCurrentUser: async (): Promise<User> => {
    try {
      const response = await axiosInstance.get<User>('/users/me');
      return response.data;
    } catch (error: any) {
      console.error('Get Current User error:', error);
      const errorMessage = error.response?.data?.detail || 'Failed to get current user.';
      toast.error(errorMessage);
      return {} as User;
    }
  },

  refreshToken: refreshAccessToken,

  requestPasswordReset: async (email: string): Promise<void> => {
    try {
      await axiosInstance.post('/auth/password/reset', { email });
    } catch (error: any) {
      console.error('Request Password Reset error:', error);
      const errorMessage = error.response?.data?.detail || 'Failed to request password reset.';
      toast.error(errorMessage);
    }
  },

  confirmPasswordReset: async (data: {
    token: string;
    new_password: string;
    confirm_password: string;
  }): Promise<void> => {
    try {
      await axiosInstance.post('/auth/password/reset-confirm', data);
    } catch (error: any) {
      console.error('Confirm Password Reset error:', error);
      const errorMessage = error.response?.data?.detail || 'Failed to confirm password reset.';
      toast.error(errorMessage);
    }
  },

  changePassword: async (data: {
    current_password: string;
    new_password: string;
  }): Promise<void> => {
    try {
      await axiosInstance.post('/auth/password/change', data);
    } catch (error: any) {
      console.error('Change Password error:', error);
      const errorMessage = error.response?.data?.detail || 'Failed to change password.';
      toast.error(errorMessage);
    }
  },
};

// Proactive refresh with synchronization
const startProactiveRefresh = () => {
  let refreshInterval: NodeJS.Timeout;

  const performProactiveRefresh = async () => {
    try {
      const accessToken = tokenStorage.getAccessToken();
      if (!accessToken) {
        return;
      }

      if (!isTokenValid(accessToken)) {
        console.log('Access token invalid or expired. Clearing and redirecting.');
        tokenStorage.clearTokens();
        if (typeof window !== 'undefined') {
          window.location.href = '/auth/login';
        }
        return;
      }

      const payload = JSON.parse(atob(accessToken.split('.')[1]));
      const exp = payload.exp * 1000;
      const now = Date.now();
      const timeUntilExpiry = exp - now;

      debugLog(`[Proactive Refresh Check] Token expires in ${Math.round(timeUntilExpiry / 1000)}s`);

      if (timeUntilExpiry < 300_000) {
        debugLog(`Token expires in ${Math.round(timeUntilExpiry / 1000)}s. Starting proactive refresh.`);
        if (!refreshTokenState.promise) {
          refreshTokenState.promise = new Promise(async (resolve, reject) => {
            try {
              const newTokenResponse = await refreshAccessToken();
              tokenStorage.setAccessToken(newTokenResponse.access_token);
              if (newTokenResponse.refresh_token) {
                tokenStorage.setRefreshToken(newTokenResponse.refresh_token);
                debugLog("🔄 New refresh token received - 30-day renewal cycle activated");
              }
              debugLog('Proactive token refresh successful');
              resolve(newTokenResponse.access_token);
            } catch (error) {
              console.error('Proactive refresh failed:', error);
              reject(error);
            } finally {
              refreshTokenState.promise = null;
            }
          });
        } else {
          debugLog('Refresh already in progress. Skipping proactive refresh.');
        }
      }
    } catch (error) {
      console.error('Proactive refresh failed:', error);
    }
  };

  // Check every 5 minutes for 1-day tokens
  refreshInterval = setInterval(performProactiveRefresh, 300_000);
  performProactiveRefresh();

  return () => {
    if (refreshInterval) {
      clearInterval(refreshInterval);
    }
  };
};

// Start proactive refresh
const stopProactiveRefresh = startProactiveRefresh();

// Cleanup function
export const cleanupTokenRefresh = () => {
  refreshTokenState.promise = null;
  refreshTokenState.attempts = 0;
  refreshTokenState.lastAttempt = 0;
  stopProactiveRefresh();
};