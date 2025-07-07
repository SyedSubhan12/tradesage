import axios, { AxiosError, AxiosRequestConfig, AxiosRequestHeaders } from 'axios';
import { User, UserRole } from './authContext';

const API_BASE_URL = '/api'; // Use relative URLs to work with Vite proxy

// ---------------------------------------------------------------------------
// Lightweight conditional logger – noisy/diagnostic output only in development
// ---------------------------------------------------------------------------
const isDev = import.meta.env.MODE !== 'production';
const debugLog = (...args: unknown[]) => {
  if (isDev) {
    // eslint-disable-next-line no-console
    console.debug(...args);
  }
};

// Create an axios instance
const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
});

// Enhanced refresh token management with exponential backoff and improved error handling
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
  maxAttempts: 3
};

// Enhanced token validation
const isTokenValid = (token: string | null): boolean => {
  if (!token) return false;
  
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    const exp = payload.exp * 1000; // Convert to milliseconds
    const now = Date.now();
    
    // Consider token valid if it doesn't expire within the next 5 minutes.
    return exp > (now + 300_000); // 5-minute buffer
  } catch (error) {
    console.error('Invalid token format:', error);
    return false;
  }
};

// Define refreshAccessToken first
const refreshAccessToken = async (): Promise<TokenResponse> => {
  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) {
    throw new Error('No refresh token available');
  }

  // Validate refresh token before attempting refresh
  if (!isTokenValid(refreshToken)) {
    console.error('Refresh token is expired or invalid');
    throw new Error('Refresh token is invalid');
  }

  // Exponential backoff calculation
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
    
    const response = await axiosInstance.post<TokenResponse>('/auth/refresh', 
      {}, // No body needed for this request
      {
        headers: {
          Authorization: `Bearer ${refreshToken}`,
        },
        timeout: 10000, // 10 second timeout
      }
    );

    // Reset attempts on success
    refreshTokenState.attempts = 0;
    refreshTokenState.lastAttempt = 0;
    
    debugLog('  Token refresh successful');
    
    // Store the new access token
    localStorage.setItem('access_token', response.data.access_token);
    
    // Handle refresh token renewal cycle
    if (response.data.refresh_token) {
      // New refresh token provided - this happens when old token is close to expiry (7 days)
      localStorage.setItem('refresh_token', response.data.refresh_token);
      debugLog("🔄 New refresh token received - 30-day renewal cycle activated");
    } else {
      // No new refresh token - continue using existing one
      debugLog("  Using existing refresh token (still valid for current 30-day cycle)");
    }
    
    return response.data;
    
  } catch (error) {
    console.error(` Token refresh failed (attempt ${refreshTokenState.attempts}):`, error);
    
    if (refreshTokenState.attempts >= refreshTokenState.maxAttempts) {
      console.error('Max refresh attempts reached. Logging out.');
      refreshTokenState.attempts = 0;
      refreshTokenState.lastAttempt = 0;
      throw new Error('Max refresh attempts exceeded');
    }
    
    throw error;
  }
};

// --- Axios Request Interceptor ---
// This interceptor will automatically add the access token to every request,
// except for the refresh token endpoint.
axiosInstance.interceptors.request.use(
  (config) => {
    // Do not add the token for the refresh endpoint
    if (config.url?.endsWith('/auth/refresh')) {
      return config;
    }

    const token = localStorage.getItem('access_token');
    // Only attach the token if the caller did NOT already set an Authorization header.
    if (token && !(config.headers && ('Authorization' in config.headers))) {
      // Axios in v1 expects `headers` to conform to `AxiosRequestHeaders` (alias of `AxiosHeaders`).
      // Build a compliant object while preserving any existing headers.
      config.headers = {
        ...(config.headers || {}),
        Authorization: `Bearer ${token}`,
      } as AxiosRequestHeaders;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// --- Axios Response Interceptor for Token Refresh (Enhanced Race Condition Protection) ---
axiosInstance.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };

    // Enhanced error handling
    if (error.response?.status !== 401 || !originalRequest) {
      // Handle specific error cases
      if (error.response?.status === 403) {
        console.error('Access forbidden. User may not have proper permissions.');
      } else if (error.response?.status === 429) {
        console.warn('Rate limit exceeded. Retrying after delay.');
        // Could implement rate limit handling here
      }
      return Promise.reject(error.response?.data || error);
    }

    // If the failed request was already for a token refresh, handle appropriately
    if (originalRequest.url?.endsWith('/auth/refresh')) {
      console.error("Refresh token is invalid or expired. Logging out.");
      
      // Clear all tokens and state
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      refreshTokenState.promise = null;
      refreshTokenState.attempts = 0;
      refreshTokenState.lastAttempt = 0;
      
      // Redirect to login
      window.location.href = '/auth/login';
      return Promise.reject(error);
    }

    // Prevent multiple refresh attempts for the same token
    if (originalRequest._retry) {
      console.error('Request already retried once. Rejecting.');
      return Promise.reject(error);
    }

    // Mark this request as being retried
    originalRequest._retry = true;

    // If no refresh is currently in progress, start one
    if (!refreshTokenState.promise) {
      debugLog("Starting new token refresh operation");
      
      refreshTokenState.promise = new Promise(async (resolve, reject) => {
        try {
          const tokenResponse = await refreshAccessToken();
          const newAccessToken = tokenResponse.access_token;

          // Validate the new token before storing
          if (!isTokenValid(newAccessToken)) {
            throw new Error('Received invalid access token from refresh');
          }

          localStorage.setItem('access_token', newAccessToken);
          
          // Handle refresh token renewal cycle
          if (tokenResponse.refresh_token) {
            // New refresh token provided - this happens when old token is close to expiry (7 days)
            localStorage.setItem('refresh_token', tokenResponse.refresh_token);
            debugLog("🔄 New refresh token received - 30-day renewal cycle activated");
          } else {
            // No new refresh token - continue using existing one
            debugLog("  Using existing refresh token (still valid for current 30-day cycle)");
          }
          
          debugLog("Token refresh operation completed successfully");
          resolve(newAccessToken);
          
        } catch (refreshError) {
          console.error("Token refresh operation failed:", refreshError);
          
          // Clear tokens on failure
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          
          // Redirect to login
          window.location.href = '/auth/login';
          reject(refreshError);
          
        } finally {
          // Clear the promise for next time
          refreshTokenState.promise = null;
        }
      });
    } else {
      debugLog("Token refresh already in progress. Waiting for completion.");
    }

    // Wait for the refresh operation to complete
    try {
      const newToken = await refreshTokenState.promise;
      
      if (newToken && originalRequest.headers) {
        // Update the original request with new token
        originalRequest.headers['Authorization'] = `Bearer ${newToken}`;
        
        // Retry the original request
        debugLog("Retrying original request with new token");
        return axiosInstance(originalRequest);
      }
      
      return Promise.reject(new Error('Token refresh completed but no valid token received'));
      
    } catch (refreshError) {
      console.error("Failed to wait for token refresh:", refreshError);
      return Promise.reject(refreshError);
    }
  }
);

// Types (can be moved to a types.ts file if they grow)
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
  refresh_token?: string; // Optional, as it's not always returned
  token_type: string;
  expires_in: number;
  tenant_status: string;
}

// Auth API calls refactored to use axios
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
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });
    return response.data;
  },

  logout: async (): Promise<void> => {
    // Explicitly attach the access token so that the backend can invalidate the session.
    const token = localStorage.getItem('access_token');
    await axiosInstance.post(
      '/auth/logout',
      {}, // no body
      {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      }
    );
  },

  getCurrentUser: async (): Promise<User> => {
    // The interceptor will add the access token automatically
    const response = await axiosInstance.get<User>('/users/me');
    return response.data;
  },

  // The refresh logic is now handled by the standalone `refreshAccessToken` function
  refreshToken: refreshAccessToken,

  requestPasswordReset: async (email: string): Promise<void> => {
    await axiosInstance.post('/auth/password/reset', { email });
  },

  confirmPasswordReset: async (data: {
    token: string;
    new_password: string;
    confirm_password: string;
  }): Promise<void> => {
    await axiosInstance.post('/auth/password/reset-confirm', data);
  },

  changePassword: async (data: {
    current_password: string;
    new_password: string;
  }): Promise<void> => {
    // The interceptor will add the access token automatically
    await axiosInstance.post('/auth/password/change', data);
  },
};

// Enhanced proactive token refresh with better error handling
const startProactiveRefresh = () => {
  let refreshInterval: NodeJS.Timeout;
  
  const performProactiveRefresh = async () => {
    try {
      const accessToken = localStorage.getItem('access_token');
      if (!accessToken) {
        // No access token found - user is likely not logged in
        // Skip this check and try again later without logging
        return;
      }

      if (!isTokenValid(accessToken)) {
        console.log('Access token is invalid or expired. Clearing and redirecting.');
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        window.location.href = '/auth/login';
        return;
      }

      const payload = JSON.parse(atob(accessToken.split('.')[1]));
      const exp = payload.exp * 1000;
      const now = Date.now();
      const timeUntilExpiry = exp - now;

      debugLog(`[Proactive Refresh Check] Token expires in ${Math.round(timeUntilExpiry / 1000)}s`);

      // Trigger refresh when the token is within 5 minutes of expiring
      if (timeUntilExpiry < 300_000) { // 5 minutes
        debugLog(`Token expires in ${Math.round(timeUntilExpiry / 1000)}s. Starting proactive refresh.`);
        
        if (!refreshTokenState.promise) {
          const newTokenResponse = await refreshAccessToken();
          localStorage.setItem('access_token', newTokenResponse.access_token);
          
          // Handle refresh token renewal cycle
          if (newTokenResponse.refresh_token) {
            // New refresh token provided - this happens when old token is close to expiry (7 days)
            localStorage.setItem('refresh_token', newTokenResponse.refresh_token);
            debugLog("🔄 New refresh token received - 30-day renewal cycle activated");
          } else {
            // No new refresh token - continue using existing one
            debugLog("  Using existing refresh token (still valid for current 30-day cycle)");
          }
          
          debugLog('  Proactive token refresh successful');
        } else {
          debugLog('Refresh already in progress. Skipping proactive refresh.');
        }
      }
    } catch (error) {
      console.error(' Proactive refresh failed:', error);
    }
  };

  // Check every minute – sufficient for 1-day tokens while keeping CPU/network low
  refreshInterval = setInterval(performProactiveRefresh, 60_000); // 1 minute
  performProactiveRefresh();
  
  return () => {
    if (refreshInterval) {
      clearInterval(refreshInterval);
    }
  };
};

// Start proactive refresh
const stopProactiveRefresh = startProactiveRefresh();

// Export cleanup function for testing or manual cleanup
export const cleanupTokenRefresh = () => {
  refreshTokenState.promise = null;
  refreshTokenState.attempts = 0;
  refreshTokenState.lastAttempt = 0;
  stopProactiveRefresh();
};
