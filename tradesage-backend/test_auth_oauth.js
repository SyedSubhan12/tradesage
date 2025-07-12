document.addEventListener('DOMContentLoaded', () => {
    // Navigation
    const navLinks = document.querySelectorAll('nav ul li a');
    const sections = document.querySelectorAll('.content .container:not(#configSection):not(#tokenStoreAreaContainer)');
    const configSection = document.getElementById('configSection');
    const tokenStoreContainer = document.getElementById('tokenStoreAreaContainer');

    function showSection(targetId) {
        sections.forEach(section => {
            if (section.id === targetId) {
                section.classList.remove('hidden');
            } else {
                section.classList.add('hidden');
            }
        });
        navLinks.forEach(link => {
            if (link.getAttribute('href') === `#${targetId}`) {
                link.classList.add('active');
            } else {
                link.classList.remove('active');
            }
        });
    }

    navLinks.forEach(link => {
        link.addEventListener('click', (event) => {
            event.preventDefault();
            const targetId = link.getAttribute('href').substring(1);
            showSection(targetId);
        });
    });

    // Show the first section by default (or a specific one)
    if (navLinks.length > 0) {
        showSection(navLinks[0].getAttribute('href').substring(1)); // Show first nav item's section
    }

    // PKCE Helper functions
    function dec2hex(dec) {
        return ('0' + dec.toString(16)).substr(-2);
    }

    function generateCodeVerifier() {
        const array = new Uint32Array(56 / 2);
        window.crypto.getRandomValues(array);
        return Array.from(array, dec2hex).join('');
    }

    async function generateCodeChallenge(verifier) {
        const encoder = new TextEncoder();
        const data = encoder.encode(verifier);
        const hash = await window.crypto.subtle.digest('SHA-256', data);
        return base64urlencode(hash);
    }

    function base64urlencode(buffer) {
        let str = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            str += String.fromCharCode(bytes[i]);
        }
        return btoa(str)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    // Store for tokens and other session data
    let testSessionStore = {
        apiBaseUrl: 'http://localhost:8000',
        codeVerifier: null,
        accessToken: null,
        refreshToken: null,
        oauthAccessToken: null,
        oauthRefreshToken: null,
        adminToken: null,
        adminUsername: 'admin@example.com',
        adminPassword: ''
    };

    function updateTokenStoreDisplay() {
        const display = {
            apiBaseUrl: testSessionStore.apiBaseUrl,
            codeVerifier: testSessionStore.codeVerifier ? testSessionStore.codeVerifier.substring(0, 30) + '...' : null,
            accessToken: testSessionStore.accessToken ? testSessionStore.accessToken.substring(0, 30) + '...' : null,
            refreshToken: testSessionStore.refreshToken ? testSessionStore.refreshToken.substring(0, 30) + '...' : null,
            oauthAccessToken: testSessionStore.oauthAccessToken ? testSessionStore.oauthAccessToken.substring(0, 30) + '...' : null,
            oauthRefreshToken: testSessionStore.oauthRefreshToken ? testSessionStore.oauthRefreshToken.substring(0, 30) + '...' : null,
            adminToken: testSessionStore.adminToken ? testSessionStore.adminToken.substring(0, 30) + '...' : null,
            adminUsername: testSessionStore.adminUsername
        };
        document.getElementById('tokenStoreArea').textContent = JSON.stringify(display, null, 2);
    }
    updateTokenStoreDisplay(); // Initial display

    // API Helper
    async function makeApiCall(endpoint, method = 'GET', body = null, headers = {}, isFormData = false) {
        const baseUrl = document.getElementById('apiBaseUrl').value || testSessionStore.apiBaseUrl;
        testSessionStore.apiBaseUrl = baseUrl; // Update store
        updateTokenStoreDisplay();

        const fullUrl = `${baseUrl}${endpoint}`;
        const options = { method, headers: { ...headers } };

        if (body) {
            if (isFormData) {
                options.body = body; // body is already FormData
            } else {
                options.body = JSON.stringify(body);
                options.headers['Content-Type'] = 'application/json';
            }
        }

        document.getElementById('responseArea').textContent = `Loading ${method} ${fullUrl}...`;

        try {
            const response = await fetch(fullUrl, options);
            const responseData = await response.json().catch(() => response.text()); // Try to parse JSON, fallback to text
            document.getElementById('responseArea').textContent = JSON.stringify({ 
                status: response.status,
                statusText: response.statusText,
                headers: Object.fromEntries(response.headers.entries()),
                data: responseData
            }, null, 2);
            return { ok: response.ok, status: response.status, data: responseData };
        } catch (error) {
            console.error('API Call Error:', error);
            document.getElementById('responseArea').textContent = JSON.stringify({ error: error.message, details: error }, null, 2);
            return { ok: false, error };
        }
    }

    // --- Configuration --- 
    window.storeAdminCredentials = async () => {
        testSessionStore.adminUsername = document.getElementById('oauthAdminUsername').value;
        testSessionStore.adminPassword = document.getElementById('oauthAdminPassword').value;
        testSessionStore.apiBaseUrl = document.getElementById('apiBaseUrl').value;
        updateTokenStoreDisplay();
        document.getElementById('responseArea').textContent = 'Admin credentials and API base URL stored in JS session.';
        // Attempt to get an admin token immediately
        if (testSessionStore.adminUsername && testSessionStore.adminPassword) {
            const formData = new FormData();
            formData.append('username', testSessionStore.adminUsername);
            formData.append('password', testSessionStore.adminPassword);
            
            const result = await makeApiCall('/auth/token', 'POST', formData, {}, true);
            if (result.ok && result.data.access_token) {
                testSessionStore.adminToken = result.data.access_token;
                updateTokenStoreDisplay();
                document.getElementById('responseArea').textContent += '\nAdmin token fetched and stored.';
            } else {
                document.getElementById('responseArea').textContent += '\nFailed to fetch admin token. Check credentials and API URL.';
            }
        }
    };

    // --- OAuth Client Management --- (Requires Admin Token)
    function getAdminAuthHeader() {
        if (!testSessionStore.adminToken) {
            alert('Admin token not available. Please store admin credentials and ensure login was successful.');
            return null;
        }
        return { 'Authorization': `Bearer ${testSessionStore.adminToken}` };
    }

    window.createOAuthClient = async () => {
        const headers = getAdminAuthHeader();
        if (!headers) return;

        const clientData = {
            redirect_uris: document.getElementById('clientRedirectUris').value.split(',').map(uri => uri.trim()),
            grant_types: document.getElementById('clientGrantTypes').value.split(',').map(gt => gt.trim()),
            scopes: document.getElementById('clientScopes').value.split(',').map(s => s.trim()),
            is_confidential: document.getElementById('isConfidential').value === 'true'
        };
        const result = await makeApiCall('/oauth/clients', 'POST', clientData, headers);
        if (result.ok && result.data.client_id) {
            document.getElementById('manageClientId').value = result.data.client_id;
            document.getElementById('authClientId').value = result.data.client_id;
            document.getElementById('refreshClientId').value = result.data.client_id;
            document.getElementById('clientCredsClientId').value = result.data.client_id;
            if (result.data.client_secret) {
                 document.getElementById('clientCredsClientSecret').value = result.data.client_secret;
                 document.getElementById('refreshClientSecret').value = result.data.client_secret;
            }
        }
    };

    window.listOAuthClients = async () => {
        const headers = getAdminAuthHeader();
        if (!headers) return;
        await makeApiCall('/oauth/clients', 'GET', null, headers);
    };

    window.getOAuthClient = async () => {
        const headers = getAdminAuthHeader();
        if (!headers) return;
        const clientId = document.getElementById('manageClientId').value;
        if (!clientId) { alert('Client ID is required.'); return; }
        await makeApiCall(`/oauth/clients/${clientId}`, 'GET', null, headers);
    };

    window.updateOAuthClient = async () => {
        const headers = getAdminAuthHeader();
        if (!headers) return;
        const clientId = document.getElementById('manageClientId').value;
        if (!clientId) { alert('Client ID is required.'); return; }
        const clientData = {
            redirect_uris: document.getElementById('clientRedirectUris').value.split(',').map(uri => uri.trim()),
            grant_types: document.getElementById('clientGrantTypes').value.split(',').map(gt => gt.trim()),
            scopes: document.getElementById('clientScopes').value.split(',').map(s => s.trim()),
            // is_confidential cannot be updated via this typical PUT, usually fixed at creation or special endpoint
        };
        await makeApiCall(`/oauth/clients/${clientId}`, 'PUT', clientData, headers);
    };

    window.deleteOAuthClient = async () => {
        const headers = getAdminAuthHeader();
        if (!headers) return;
        const clientId = document.getElementById('manageClientId').value;
        if (!clientId) { alert('Client ID is required.'); return; }
        if (confirm(`Are you sure you want to delete client ${clientId}?`)) {
            await makeApiCall(`/oauth/clients/${clientId}`, 'DELETE', null, headers);
        }
    };

    // --- Authorization Code Flow (PKCE) ---
    window.startAuthCodeFlow = async () => {
        const clientId = document.getElementById('authClientId').value;
        const redirectUri = document.getElementById('authRedirectUri').value;
        const scope = document.getElementById('authScope').value;
        const baseUrl = document.getElementById('apiBaseUrl').value;

        if (!clientId || !redirectUri) {
            alert('Client ID and Redirect URI are required for Auth Code Flow.');
            return;
        }

        testSessionStore.codeVerifier = generateCodeVerifier();
        const codeChallenge = await generateCodeChallenge(testSessionStore.codeVerifier);
        updateTokenStoreDisplay();

        const authUrl = new URL(`${baseUrl}/oauth/authorize`);
        authUrl.searchParams.append('response_type', 'code');
        authUrl.searchParams.append('client_id', clientId);
        authUrl.searchParams.append('redirect_uri', redirectUri);
        authUrl.searchParams.append('scope', scope);
        authUrl.searchParams.append('code_challenge', codeChallenge);
        authUrl.searchParams.append('code_challenge_method', 'S256');
        
        document.getElementById('responseArea').textContent = `Redirecting to: ${authUrl.toString()}`;
        window.location.href = authUrl.toString();
    };

    // Call this on page load to handle redirect from auth server
    async function handleAuthCodeRedirect() {
        const urlParams = new URLSearchParams(window.location.search);
        const code = urlParams.get('code');
        if (code) {
            document.getElementById('authCode').value = code;
            document.getElementById('responseArea').textContent = 'Authorization code received from redirect.';
            // Populate client_id and redirect_uri if possible from stored state or defaults
            if(localStorage.getItem('pkce_client_id')){
                document.getElementById('authClientId').value = localStorage.getItem('pkce_client_id');
            }
            if(localStorage.getItem('pkce_redirect_uri')){
                 document.getElementById('authRedirectUri').value = localStorage.getItem('pkce_redirect_uri');
            }
            // Clean the URL
            window.history.replaceState({}, document.title, window.location.pathname);
            showSection('authCodeSection'); // Switch to auth code section
        }
    }
    handleAuthCodeRedirect(); // Check for code on every load

    window.exchangeCodeForToken = async () => {
        const code = document.getElementById('authCode').value;
        const clientId = document.getElementById('authClientId').value;
        const redirectUri = document.getElementById('authRedirectUri').value;
        
        if (!code || !testSessionStore.codeVerifier) {
            alert('Auth code or code verifier missing. Complete step 1 first.');
            return;
        }

        const formData = new FormData();
        formData.append('grant_type', 'authorization_code');
        formData.append('code', code);
        formData.append('redirect_uri', redirectUri);
        formData.append('client_id', clientId);
        formData.append('code_verifier', testSessionStore.codeVerifier);

        // For public clients, client_secret is not sent.
        // If your client is confidential and requires it for the token endpoint, add it here.
        // const clientSecret = document.getElementById('authClientSecret').value; // Assuming you have such an input
        // if (clientSecret) formData.append('client_secret', clientSecret);

        const result = await makeApiCall('/oauth/token', 'POST', formData, {}, true);
        if (result.ok && result.data.access_token) {
            testSessionStore.oauthAccessToken = result.data.access_token;
            testSessionStore.oauthRefreshToken = result.data.refresh_token;
            document.getElementById('oauthRefreshToken').value = result.data.refresh_token || '';
            updateTokenStoreDisplay();
        }
        testSessionStore.codeVerifier = null; // Clear verifier after use
        updateTokenStoreDisplay();
    };

    // --- OAuth Refresh Token Flow ---
    window.refreshOAuthToken = async () => {
        const refreshToken = document.getElementById('oauthRefreshToken').value;
        const clientId = document.getElementById('refreshClientId').value;
        const clientSecret = document.getElementById('refreshClientSecret').value; // Required for confidential clients

        if (!refreshToken || !clientId) {
            alert('Refresh token and Client ID are required.');
            return;
        }

        const formData = new FormData();
        formData.append('grant_type', 'refresh_token');
        formData.append('refresh_token', refreshToken);
        formData.append('client_id', clientId);
        if (clientSecret) {
            formData.append('client_secret', clientSecret);
        }

        const result = await makeApiCall('/oauth/token', 'POST', formData, {}, true);
        if (result.ok && result.data.access_token) {
            testSessionStore.oauthAccessToken = result.data.access_token;
            testSessionStore.oauthRefreshToken = result.data.refresh_token; // Usually a new refresh token is issued
            document.getElementById('oauthRefreshToken').value = result.data.refresh_token || '';
            updateTokenStoreDisplay();
        }
    };

    // --- OAuth Client Credentials Flow ---
    window.getClientCredentialsToken = async () => {
        const clientId = document.getElementById('clientCredsClientId').value;
        const clientSecret = document.getElementById('clientCredsClientSecret').value;

        if (!clientId || !clientSecret) {
            alert('Client ID and Client Secret are required.');
            return;
        }

        const formData = new FormData();
        formData.append('grant_type', 'client_credentials');
        formData.append('client_id', clientId);
        formData.append('client_secret', clientSecret);

        const result = await makeApiCall('/oauth/token', 'POST', formData, {}, true);
        if (result.ok && result.data.access_token) {
            testSessionStore.oauthAccessToken = result.data.access_token; // No refresh token in client_credentials
            testSessionStore.oauthRefreshToken = null;
            updateTokenStoreDisplay();
        }
    };

    // --- User Authentication (Session based) ---
    function getUserAuthHeader() {
        if (!testSessionStore.accessToken) {
            alert('User access token not available. Please login first.');
            return null;
        }
        return { 'Authorization': `Bearer ${testSessionStore.accessToken}` };
    }

    window.loginUser = async () => {
        const username = document.getElementById('userEmail').value;
        const password = document.getElementById('userPassword').value;

        if (!username || !password) {
            alert('Email and password are required.');
            return;
        }

        const formData = new FormData();
        formData.append('username', username);
        formData.append('password', password);

        const result = await makeApiCall('/auth/token', 'POST', formData, {}, true);
        if (result.ok && result.data.access_token) {
            testSessionStore.accessToken = result.data.access_token;
            testSessionStore.refreshToken = result.data.refresh_token;
            document.getElementById('sessionRefreshToken').value = result.data.refresh_token || '';
            updateTokenStoreDisplay();
        }
    };

    window.refreshSessionToken = async () => {
        const refreshToken = document.getElementById('sessionRefreshToken').value;
        if (!refreshToken) {
            alert('Session refresh token is required.');
            return;
        }
        const headers = { 'Authorization': `Bearer ${refreshToken}` }; // Send refresh token as Bearer
        const result = await makeApiCall('/auth/refresh', 'POST', null, headers);
        if (result.ok && result.data.access_token) {
            testSessionStore.accessToken = result.data.access_token;
            testSessionStore.refreshToken = result.data.refresh_token;
            document.getElementById('sessionRefreshToken').value = result.data.refresh_token || '';
            updateTokenStoreDisplay();
        }
    };

    window.logoutUser = async () => {
        const headers = getUserAuthHeader();
        if (!headers) return;
        await makeApiCall('/auth/logout', 'POST', null, headers);
        testSessionStore.accessToken = null;
        testSessionStore.refreshToken = null;
        document.getElementById('sessionRefreshToken').value = '';
        updateTokenStoreDisplay();
    };

    // --- Password Management ---
    window.changePassword = async () => {
        const headers = getUserAuthHeader();
        if (!headers) return;

        const oldPassword = document.getElementById('changePassOld').value;
        const newPassword = document.getElementById('changePassNew').value;

        if (!oldPassword || !newPassword) {
            alert('Old and new passwords are required.');
            return;
        }
        await makeApiCall('/auth/password/change', 'POST', { old_password: oldPassword, new_password: newPassword }, headers);
    };

    window.requestPasswordReset = async () => {
        const email = document.getElementById('resetPassEmail').value;
        if (!email) {
            alert('Email is required for password reset request.');
            return;
        }
        await makeApiCall('/auth/password/reset-request', 'POST', { email: email });
    };

    window.confirmPasswordReset = async () => {
        const token = document.getElementById('resetToken').value;
        const newPassword = document.getElementById('newPasswordConfirm').value;
        if (!token || !newPassword) {
            alert('Reset token and new password are required.');
            return;
        }
        await makeApiCall('/auth/password/reset-confirm', 'POST', { token: token, new_password: newPassword });
    };

});
