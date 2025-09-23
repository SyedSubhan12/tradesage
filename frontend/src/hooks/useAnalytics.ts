import { useState, useEffect, useCallback } from 'react';

export interface UserInteraction {
  interaction_type: string;
  metadata: Record<string, any>;
  session_id?: string;
}

export interface DashboardPersonalization {
  priority_symbols: Array<{
    symbol: string;
    dataset: string;
    priority: number;
  }>;
  relevant_news_keywords: string[];
  suggested_timeframes: string[];
  recommended_strategies: string[];
  market_focus: string[];
  widget_priorities: Record<string, number>;
}

export interface PersonalizedMarketData {
  priority_indices: Array<{
    name: string;
    value: string;
    change: string;
    positive: boolean;
  }>;
  user_symbols: Array<{
    symbol: string;
    dataset: string;
    priority: number;
  }>;
  suggested_timeframes: string[];
  market_focus: string[];
}

export interface UserPreferences {
  preferred_symbols: string[];
  preferred_datasets: string[];
  preferred_timeframes: string[];
  favorite_news_categories: string[];
  trading_style: string;
  risk_tolerance: string;
  active_hours: number[];
  last_updated: string;
}

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8002';

export const useAnalytics = () => {
  const [personalization, setPersonalization] = useState<DashboardPersonalization | null>(null);
  const [marketData, setMarketData] = useState<PersonalizedMarketData | null>(null);
  const [preferences, setPreferences] = useState<UserPreferences | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Generate a simple user ID based on browser fingerprint or use a default
  const getUserId = useCallback(() => {
    // In a real app, this would come from authentication
    // For now, use a simple browser-based ID
    let userId = localStorage.getItem('user_id');
    if (!userId) {
      userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      localStorage.setItem('user_id', userId);
    }
    return userId;
  }, []);

  // Track user interaction
  const trackInteraction = useCallback(async (interaction: UserInteraction) => {
    try {
      const userId = getUserId();
      const response = await fetch(`${API_BASE_URL}/api/v1/analytics/track`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-User-ID': userId,
        },
        body: JSON.stringify(interaction),
      });

      if (!response.ok) {
        console.warn('Failed to track interaction:', response.statusText);
      }
    } catch (error) {
      console.warn('Error tracking interaction:', error);
    }
  }, [getUserId]);

  // Fetch dashboard personalization
  const fetchPersonalization = useCallback(async () => {
    try {
      const userId = getUserId();
      const response = await fetch(`${API_BASE_URL}/api/v1/analytics/dashboard/personalization`, {
        headers: {
          'X-User-ID': userId,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setPersonalization(data);
      } else {
        throw new Error('Failed to fetch personalization');
      }
    } catch (error) {
      console.error('Error fetching personalization:', error);
      setError('Failed to load personalization');
    }
  }, [getUserId]);

  // Fetch personalized market data
  const fetchMarketData = useCallback(async () => {
    try {
      const userId = getUserId();
      const response = await fetch(`${API_BASE_URL}/api/v1/analytics/dashboard/market-data`, {
        headers: {
          'X-User-ID': userId,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setMarketData(data);
      } else {
        throw new Error('Failed to fetch market data');
      }
    } catch (error) {
      console.error('Error fetching market data:', error);
      setError('Failed to load market data');
    }
  }, [getUserId]);

  // Fetch user preferences
  const fetchPreferences = useCallback(async () => {
    try {
      const userId = getUserId();
      const response = await fetch(`${API_BASE_URL}/api/v1/analytics/user/preferences`, {
        headers: {
          'X-User-ID': userId,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setPreferences(data);
      } else {
        throw new Error('Failed to fetch preferences');
      }
    } catch (error) {
      console.error('Error fetching preferences:', error);
      setError('Failed to load preferences');
    }
  }, [getUserId]);

  // Simulate user activity for testing
  const simulateActivity = useCallback(async () => {
    try {
      const userId = getUserId();
      const response = await fetch(`${API_BASE_URL}/api/v1/analytics/simulate-activity`, {
        method: 'POST',
        headers: {
          'X-User-ID': userId,
        },
      });

      if (response.ok) {
        // Refresh data after simulation
        await Promise.all([
          fetchPersonalization(),
          fetchMarketData(),
          fetchPreferences(),
        ]);
      }
    } catch (error) {
      console.error('Error simulating activity:', error);
    }
  }, [getUserId, fetchPersonalization, fetchMarketData, fetchPreferences]);

  // Load all analytics data
  const loadAnalyticsData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      await Promise.all([
        fetchPersonalization(),
        fetchMarketData(),
        fetchPreferences(),
      ]);
    } catch (error) {
      console.error('Error loading analytics data:', error);
      setError('Failed to load analytics data');
    } finally {
      setLoading(false);
    }
  }, [fetchPersonalization, fetchMarketData, fetchPreferences]);

  // Track dashboard view on mount
  useEffect(() => {
    trackInteraction({
      interaction_type: 'dashboard_view',
      metadata: {
        timestamp: new Date().toISOString(),
        page: 'dashboard',
      },
    });

    loadAnalyticsData();
  }, [trackInteraction, loadAnalyticsData]);

  return {
    personalization,
    marketData,
    preferences,
    loading,
    error,
    trackInteraction,
    simulateActivity,
    refreshData: loadAnalyticsData,
  };
};
