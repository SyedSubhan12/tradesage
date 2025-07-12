// api-client.js

const API_BASE_URL = 'http://127.0.0.1:8000'; // Update this if your auth service URL differs

// Utility to pretty-print JSON in the UI
function formatJSON(json) {
  return JSON.stringify(json, null, 2);
}

// Update a given element’s text content with the API response (and colorize if error)
function updateResponseStatus(elementId, response, isError = false) {
  const element = document.getElementById(elementId);
  if (!element) return;
  element.textContent = formatJSON(response);
  element.style.color = isError ? '#e74c3c' : '#ecf0f1';
}

// Enhanced logging: write to console and keep the last 50 entries in sessionStorage
function logOperation(operation, data, response = null, error = null) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    operation,
    data: data ? (typeof data === 'string' ? data : JSON.stringify(data, null, 2)) : null,
    response: response ? JSON.stringify(response, null, 2) : null,
    error: error ? error.toString() : null
  };

  console.log(`[${timestamp}] ${operation}:`, logEntry);

  // Keep last 50 logs in sessionStorage
  const logs = JSON.parse(sessionStorage.getItem('api_logs') || '[]');
  logs.push(logEntry);
  if (logs.length > 50) logs.splice(0, logs.length - 50);
  sessionStorage.setItem('api_logs', JSON.stringify(logs));
}

// Generic fetch wrapper
async function callApi(endpoint, method, data = null, token = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const config = { method, headers };
  if (data && method !== 'GET') {
    config.body = JSON.stringify(data);
  }

  logOperation(`API Call - ${method} ${endpoint}`, {
    headers: { ...headers, Authorization: token ? 'Bearer [REDACTED]' : undefined },
    body: data
  });

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, config);
    const result = await response.json();
    logOperation(`API Response - ${method} ${endpoint}`, null, {
      status: response.status,
      data: result
    });
    return { status: response.status, data: result };
  } catch (error) {
    logOperation(`API Error - ${method} ${endpoint}`, null, null, error);
    return { status: 500, error: error.message };
  }
}

// ------------------- API FUNCTIONS -------------------

async function testHealthCheck() {
  logOperation('Health Check Started');
  const response = await callApi('/health', 'GET');
  updateResponseStatus('healthStatus', response.data);
  return response;
}

async function registerUser(username, email, password, first_name, last_name, role) {
  const userData = { username, email, password: '[REDACTED]', first_name, last_name, role };
  logOperation('User Registration Started', userData);

  const actualUserData = { username, email, password, first_name, last_name, role };
  try {
    const response = await callApi('/users/register', 'POST', actualUserData);
    updateResponseStatus('registerStatus', response.data);
    logOperation('User Registration Result', null, response);
    return response;
  } catch (error) {
    logOperation('User Registration Error', null, null, error);
    updateResponseStatus('registerStatus', { error: error.message }, true);
    return { status: 500, error: error.message };
  }
}

async function loginUser(email, password) {
  logOperation('Login Started', { email, password: '[REDACTED]' });
  if (!email || !password) {
    const error = 'Email and password are required';
    logOperation('Login Validation Error', null, null, error);
    updateResponseStatus('loginStatus', { error }, true);
    return { status: 400, error };
  }

  try {
    // OAuth2PasswordRequestForm requires grant_type=password
    const form = new URLSearchParams();
    form.append('grant_type', 'password');
    form.append('username', email);
    form.append('password', password);

    logOperation('Login Request', `Attempting login for ${email}`);

    const response = await fetch(`${API_BASE_URL}/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString()
    });

    logOperation('Login Response Received', `Status: ${response.status}, OK: ${response.ok}`);

    if (!response.ok) {
      const errorText = await response.text();
      logOperation('Login Failed - Response Error', null, { status: response.status, error: errorText });
      const errorData = { error: `Login failed: ${errorText}`, status: response.status };
      updateResponseStatus('loginStatus', errorData, true);
      return { status: response.status, error: errorText };
    }

    const result = await response.json();
    logOperation('Login Success - Token Received', null, { status: response.status, hasToken: !!result.access_token });

    // Show sanitized tokens in UI
    const sanitizedResult = {
      ...result,
      access_token: result.access_token ? '[TOKEN_RECEIVED]' : null,
      refresh_token: result.refresh_token ? '[REFRESH_TOKEN_RECEIVED]' : null
    };
    updateResponseStatus('loginStatus', sanitizedResult);

    if (result.access_token) {
      try {
        sessionStorage.setItem('auth_token', result.access_token);
        sessionStorage.setItem('refresh_token', result.refresh_token || '');
        document.getElementById('currentToken').textContent = result.access_token.substring(0, 20) + '...';
        logOperation('Login Tokens Stored', 'Tokens saved to sessionStorage');
      } catch (storageError) {
        logOperation('Token Storage Error', null, null, storageError);
      }
    }

    return { status: response.status, data: result };
  } catch (error) {
    logOperation('Login Network Error', null, null, error);
    const errorData = { error: `Network error: ${error.message}` };
    updateResponseStatus('loginStatus', errorData, true);
    return { status: 500, error: error.message };
  }
}

async function verifyToken(token) {
  const response = await callApi('/auth/verify-token', 'GET', null, token);
  updateResponseStatus('tokenStatus', response.data);
  return response;
}

async function refreshToken(refreshTokenValue) {
  if (!refreshTokenValue) {
    alert('No refresh token available. Please log in first.');
    return;
  }

  logOperation('Token Refresh Started', { hasRefreshToken: !!refreshTokenValue });

  try {
    // Send refresh JWT as a cookie
    const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include', // Ensure cookies are sent
      // no body needed
    });

    const result = await response.json();
    logOperation('Token Refresh Response', null, { status: response.status, data: result });
    updateResponseStatus('tokenStatus', result);

    if (response.ok && result.access_token) {
      sessionStorage.setItem('auth_token', result.access_token);
      sessionStorage.setItem('refresh_token', result.refresh_token);
      document.getElementById('currentToken').textContent = result.access_token.substring(0, 20) + '...';
      logOperation('Token Refresh Success', 'New tokens stored');
    } else if (!response.ok) {
      logOperation('Token Refresh Failed', null, { status: response.status, data: result });
    }

    return { status: response.status, data: result };
  } catch (error) {
    logOperation('Token Refresh Network Error', null, null, error);
    updateResponseStatus('tokenStatus', { error: error.message }, true);
    return { status: 500, error: error.message };
  }
}

async function logoutUser(refreshTokenValue) {
  logOperation('Logout Started', { hasRefreshToken: !!refreshTokenValue });
  const response = await callApi('/auth/logout', 'POST', null, refreshTokenValue);
  updateResponseStatus('tokenStatus', response.data);

  if (response.status === 200) {
    sessionStorage.removeItem('auth_token');
    sessionStorage.removeItem('refresh_token');
    document.getElementById('currentToken').textContent = 'No token';
    logOperation('Logout Success', 'Tokens cleared');
  }

  return response;
}

async function getCurrentUser(token) {
  logOperation('Get Current User Started', { hasToken: !!token });
  const response = await callApi('/users/me', 'GET', null, token);
  updateResponseStatus('userStatus', response.data);
  return response;
}

async function changePassword(currentPassword, newPassword, token) {
  logOperation('Password Change Started', { hasToken: !!token });
  const passwordData = {
    current_password: currentPassword,
    new_password: newPassword,
    confirm_password: newPassword
  };

  const response = await callApi('/auth/password/change', 'POST', passwordData, token);
  updateResponseStatus('passwordStatus', response.data);
  return response;
}

async function requestPasswordReset(email) {
  logOperation('Password Reset Request Started', { email });
  const resetData = { email };
  const response = await callApi('/auth/password/reset-request', 'POST', resetData);
  updateResponseStatus('passwordStatus', response.data);
  return response;
}

async function confirmPasswordReset(token, newPassword) {
  logOperation('Password Reset Confirmation Started', { hasToken: !!token });
  const confirmData = {
    token,
    new_password: newPassword,
    confirm_password: newPassword
  };

  const response = await callApi('/auth/password/reset-confirm', 'POST', confirmData);
  updateResponseStatus('passwordStatus', response.data);
  return response;
}

async function getTenantStatus(tenantId) {
  logOperation('Tenant Status Check Started', { tenantId });
  const response = await callApi(`/tenant/status/${tenantId}`, 'GET');
  updateResponseStatus('tenantStatus', response.data);
  return response;
}

// Utility functions for logs
function viewLogs() {
  const logs = JSON.parse(sessionStorage.getItem('api_logs') || '[]');
  console.table(logs);
  return logs;
}

function clearLogs() {
  sessionStorage.removeItem('api_logs');
  logOperation('Logs Cleared', 'All API logs have been cleared');
}

// ------------------- UI EVENT LISTENERS -------------------

document.addEventListener('DOMContentLoaded', () => {
  logOperation('DOM Content Loaded', 'Initializing application');

  // Restore token display if present
  const savedToken = sessionStorage.getItem('auth_token');
  if (savedToken) {
    document.getElementById('currentToken').textContent = savedToken.substring(0, 20) + '...';
    logOperation('Token Restored', 'Token loaded from sessionStorage');
  }

  // Tab navigation (if tabs exist in your HTML)
  const tabButtons = document.querySelectorAll('.tab-button');
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
      button.classList.add('active');
      const tabId = button.getAttribute('data-tab');
      document.getElementById(`${tabId}-tab`).classList.add('active');
    });
  });

  // Health Check
  document.getElementById('healthCheckButton')?.addEventListener('click', testHealthCheck);

  // Register
  document.getElementById('registerButton')?.addEventListener('click', () => {
    const username = document.getElementById('registerUsername').value;
    const email = document.getElementById('registerEmail').value;
    const password = document.getElementById('registerPassword').value;
    const firstName = document.getElementById('registerFirstName').value;
    const lastName = document.getElementById('registerLastName').value;
    const role = document.getElementById('registerRole').value;

    if (!username || !email || !password) {
      alert('Username, email, and password are required!');
      return;
    }

    registerUser(username, email, password, firstName, lastName, role).then(response => {
      if (response.status === 422) {
        let errorMessage = 'Validation error';
        if (response.data && response.data.errors) {
          errorMessage = response.data.errors.map(err => `${err.field}: ${err.message}`).join('\n');
        }
        alert(`Registration failed: ${errorMessage}`);
      } else if (response.status >= 400) {
        alert(`Registration failed: ${response.data.detail || 'Unknown error'}`);
      } else if (response.status === 200) {
        alert('Registration successful! You can now log in.');
      }
    });
  });

  // Login
  document.getElementById('loginButton')?.addEventListener('click', () => {
    const email = document.getElementById('loginEmail').value;
    const password = document.getElementById('loginPassword').value;

    if (!email || !password) {
      alert('Email and password are required!');
      return;
    }

    loginUser(email, password)
      .then(response => {
        if (response.status >= 200 && response.status < 300) {
          alert('Login successful!');
        } else {
          alert(`Login failed: ${response.error || 'Unknown error'}`);
        }
      })
      .catch(error => {
        alert(`Login error: ${error.message}`);
      });
  });

  // Verify Token
  document.getElementById('verifyTokenButton')?.addEventListener('click', () => {
    const token = sessionStorage.getItem('auth_token');
    if (!token) {
      alert('No token available. Please log in first.');
      return;
    }
    verifyToken(token);
  });

  // Refresh Token
  document.getElementById('refreshTokenButton')?.addEventListener('click', () => {
    const refreshTokenValue = sessionStorage.getItem('refresh_token');
    if (!refreshTokenValue) {
      alert('No refresh token available. Please log in first.');
      return;
    }
    refreshToken(refreshTokenValue);
  });

  // Logout
  document.getElementById('logoutButton')?.addEventListener('click', () => {
    const refreshTokenValue = sessionStorage.getItem('refresh_token');
    if (!refreshTokenValue) {
      alert('No refresh token available. Please log in first.');
      return;
    }
    logoutUser(refreshTokenValue);
  });

  // Get Current User
  document.getElementById('getCurrentUserButton')?.addEventListener('click', () => {
    const token = sessionStorage.getItem('auth_token');
    if (!token) {
      alert('No token available. Please log in first.');
      return;
    }
    getCurrentUser(token);
  });

  // Change Password
  document.getElementById('changePasswordButton')?.addEventListener('click', () => {
    const token = sessionStorage.getItem('auth_token');
    if (!token) {
      alert('No token available. Please log in first.');
      return;
    }

    const currentPassword = document.getElementById('changeOldPassword').value;
    const newPassword = document.getElementById('changeNewPassword').value;

    if (!currentPassword || !newPassword) {
      alert('Current and new passwords are required!');
      return;
    }

    changePassword(currentPassword, newPassword, token);
  });

  // Request Password Reset
  document.getElementById('requestResetButton')?.addEventListener('click', () => {
    const email = document.getElementById('resetEmail').value;
    if (!email) {
      alert('Email is required!');
      return;
    }
    requestPasswordReset(email);
  });

  // Confirm Password Reset
  document.getElementById('confirmResetButton')?.addEventListener('click', () => {
    const token = document.getElementById('confirmResetToken').value;
    const newPassword = document.getElementById('confirmResetNewPassword').value;

    if (!token || !newPassword) {
      alert('Token and new password are required!');
      return;
    }

    confirmPasswordReset(token, newPassword);
  });

  // Get Tenant Status
  document.getElementById('getTenantStatusButton')?.addEventListener('click', () => {
    const tenantId = document.getElementById('tenantId').value;
    if (!tenantId) {
      alert('Tenant ID is required!');
      return;
    }
    getTenantStatus(tenantId);
  });

  // Expose log utilities (if you want to call from console)
  window.viewLogs = viewLogs;
  window.clearLogs = clearLogs;

  logOperation('Application Initialized', 'All event listeners attached');
});

// Export functions if used as module
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    loginUser,
    registerUser,
    verifyToken,
    refreshToken,
    logoutUser,
    getCurrentUser,
    changePassword,
    requestPasswordReset,
    confirmPasswordReset,
    getTenantStatus,
    viewLogs,
    clearLogs
  };
}
