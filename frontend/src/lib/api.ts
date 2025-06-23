import axios, { AxiosError, AxiosRequestConfig, AxiosRequestHeaders } from 'axios';
import { User, UserRole } from './authContext';

const API_BASE_URL = '/api'; // Use relative URLs to work with Vite proxy

// Create an axios instance
const axiosInstance = axios.create({
  baseURL: API_BASE_URL,
});

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

// --- Axios Response Interceptor for Token Refresh (Race Condition Handled) ---

// A single promise to which all concurrent requests can subscribe.
let refreshTokenPromise: Promise<string | null> | null = null;

axiosInstance.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };

    // Reject if not a 401, or if the request has no config.
    if (error.response?.status !== 401 || !originalRequest) {
      return Promise.reject(error.response?.data || error);
    }

    // If the failed request was already for a token refresh, then the refresh token is bad.
    // We must stop and log out the user.
    if (originalRequest.url?.endsWith('/auth/refresh')) {
      console.error("Refresh token is invalid or expired. Logging out.");
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      refreshTokenPromise = null;
      window.location.href = '/auth/login';
      return Promise.reject(error);
    }

    // If no refresh is currently in progress, start one.
    if (!refreshTokenPromise) {
      console.log("No refresh in progress. Starting a new one.");
      refreshTokenPromise = new Promise(async (resolve, reject) => {
        try {
          console.log('Access token expired. Attempting to refresh...');
          const tokenResponse = await refreshAccessToken();
          const newAccessToken = tokenResponse.access_token;

          localStorage.setItem('access_token', newAccessToken);
          if (tokenResponse.refresh_token) {
            localStorage.setItem('refresh_token', tokenResponse.refresh_token);
            console.log("New refresh token stored.");
          }
          
          console.log("Token refresh successful.");
          resolve(newAccessToken);
        } catch (refreshError) {
          console.error("Failed to refresh token. Logging out.", refreshError);
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          window.location.href = '/auth/login';
          reject(refreshError);
        } finally {
          // The refresh attempt is complete, so clear the promise for the next time.
          refreshTokenPromise = null;
        }
      });
    } else {
      console.log("A refresh is already in progress. Waiting for it to complete.");
    }

    // Wait for the single refresh promise to resolve, then retry the original request.
    return refreshTokenPromise.then((token) => {
      if (token && originalRequest.headers) {
        originalRequest.headers['Authorization'] = 'Bearer ' + token;
        return axiosInstance(originalRequest);
      }
      // If token is null (which shouldn't happen here, but as a safeguard), reject.
      return Promise.reject(error);
    });
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



// --- Definitive Fix: Separate function for refreshing the token ---
// This function calls the refresh endpoint directly, bypassing the interceptor logic
// that adds the access token, and instead sends the refresh token.
const refreshAccessToken = async (): Promise<TokenResponse> => {
  const refreshToken = localStorage.getItem('refresh_token');
  if (!refreshToken) {
    return Promise.reject(new Error('No refresh token available'));
  }

  console.log("🚀 Sending to /auth/refresh with REFRESH token:", refreshToken);
  const response = await axiosInstance.post<TokenResponse>('/auth/refresh', 
    {}, // No body needed for this request
    {
      headers: {
        // Explicitly set the Authorization header with the refresh token
        Authorization: `Bearer ${refreshToken}`,
      },
    }
  );
  return response.data;
};

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
