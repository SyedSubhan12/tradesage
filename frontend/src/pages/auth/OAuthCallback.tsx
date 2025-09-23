import { useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import { useAuth } from '@/lib/authContext';

const OAuthCallback = () => {
  const { handleOAuthCallback, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const searchParams = new URLSearchParams(location.search);
  const error = searchParams.get('error');
  const processed = useRef(false);

  useEffect(() => {
    // If already authenticated, redirect to dashboard
    if (isAuthenticated) {
      navigate('/dashboard');
      return;
    }

    // Prevent this effect from running twice in React StrictMode
    if (processed.current) {
      return;
    }
    processed.current = true;

    const processCallback = async () => {
      if (error) {
        console.error('OAuth error:', error);
        navigate('/auth/login', { 
          state: { 
            error: 'Failed to authenticate with Google',
            errorDetails: error 
          },
          replace: true
        });
        return;
      }

      try {
        // Extract tokens from URL fragment
        const fragment = window.location.hash.substring(1);
        console.log('OAuth Callback Fragment:', fragment); // Debugging line
        const params = new URLSearchParams(fragment);
        const accessToken = params.get('access_token');
        const refreshToken = params.get('refresh_token');

        if (!accessToken || !refreshToken) {
          throw new Error('Missing authentication tokens in the URL fragment');
        }

        // Clear the URL fragment to prevent re-processing on re-renders
        window.history.replaceState({}, document.title, window.location.pathname + window.location.search);

        // Process the OAuth callback
        await handleOAuthCallback(accessToken, refreshToken);
        
      } catch (error) {
        console.error('OAuth callback error:', error);
        navigate('/auth/login', { 
          state: { 
            error: 'Failed to complete authentication',
            errorDetails: error instanceof Error ? error.message : 'Unknown error'
          },
          replace: true
        });
      }
    };

    processCallback();
  }, [error, handleOAuthCallback, navigate, isAuthenticated]);

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <div className="text-center">
        <Loader2 className="w-12 h-12 mx-auto mb-4 text-blue-600 animate-spin" />
        <p className="text-lg font-medium text-gray-900">Completing authentication...</p>
        <p className="text-sm text-gray-500">Please wait while we log you in.</p>
      </div>
    </div>
  );
};

export default OAuthCallback;
