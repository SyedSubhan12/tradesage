"""
User Analytics Service for Dynamic Dashboard Content

This service tracks user behavior and preferences to provide personalized dashboard content.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class UserInteractionType(Enum):
    """Types of user interactions to track"""
    SYMBOL_VIEW = "symbol_view"
    CHART_VIEW = "chart_view"
    TIMEFRAME_CHANGE = "timeframe_change"
    DATASET_ACCESS = "dataset_access"
    SIGNAL_CLICK = "signal_click"
    NEWS_CLICK = "news_click"
    BACKTEST_RUN = "backtest_run"
    STRATEGY_UPLOAD = "strategy_upload"
    DASHBOARD_VIEW = "dashboard_view"


@dataclass
class UserInteraction:
    """Represents a single user interaction"""
    user_id: str
    interaction_type: UserInteractionType
    timestamp: datetime
    metadata: Dict[str, Any]
    session_id: Optional[str] = None


@dataclass
class UserPreferences:
    """User preferences derived from analytics"""
    preferred_symbols: List[str]
    preferred_datasets: List[str]
    preferred_timeframes: List[str]
    favorite_news_categories: List[str]
    trading_style: str  # "day_trader", "swing_trader", "long_term"
    risk_tolerance: str  # "low", "medium", "high"
    active_hours: List[int]  # Hours of day when most active
    last_updated: datetime


@dataclass
class DashboardPersonalization:
    """Personalized dashboard configuration"""
    priority_symbols: List[Dict[str, Any]]
    relevant_news_keywords: List[str]
    suggested_timeframes: List[str]
    recommended_strategies: List[str]
    market_focus: List[str]  # ["stocks", "crypto", "forex", "commodities"]
    widget_priorities: Dict[str, int]  # Widget name -> priority score


class UserAnalyticsService:
    """Service for tracking user analytics and generating personalized content"""
    
    def __init__(self, redis_service=None, db_manager=None):
        self.redis_service = redis_service
        self.db_manager = db_manager
        self.interactions_cache = {}  # In-memory cache for recent interactions
        
    async def track_interaction(self, interaction: UserInteraction) -> None:
        """Track a user interaction"""
        try:
            # Store in Redis for fast access
            if self.redis_service:
                key = f"user_interactions:{interaction.user_id}"
                interaction_data = {
                    "type": interaction.interaction_type.value,
                    "timestamp": interaction.timestamp.isoformat(),
                    "metadata": interaction.metadata,
                    "session_id": interaction.session_id
                }
                await self.redis_service.lpush(key, json.dumps(interaction_data))
                # Keep only last 1000 interactions per user
                await self.redis_service.ltrim(key, 0, 999)
                
            # Also store in memory cache for immediate access
            if interaction.user_id not in self.interactions_cache:
                self.interactions_cache[interaction.user_id] = []
            self.interactions_cache[interaction.user_id].append(interaction)
            
            # Keep only last 100 interactions in memory
            if len(self.interactions_cache[interaction.user_id]) > 100:
                self.interactions_cache[interaction.user_id] = self.interactions_cache[interaction.user_id][-100:]
                
        except Exception as e:
            logger.error(f"Error tracking interaction: {e}")
    
    async def get_user_interactions(self, user_id: str, limit: int = 100) -> List[UserInteraction]:
        """Get recent user interactions"""
        try:
            interactions = []
            
            # Try Redis first
            if self.redis_service:
                key = f"user_interactions:{user_id}"
                raw_interactions = await self.redis_service.lrange(key, 0, limit - 1)
                for raw_interaction in raw_interactions:
                    data = json.loads(raw_interaction)
                    interaction = UserInteraction(
                        user_id=user_id,
                        interaction_type=UserInteractionType(data["type"]),
                        timestamp=datetime.fromisoformat(data["timestamp"]),
                        metadata=data["metadata"],
                        session_id=data.get("session_id")
                    )
                    interactions.append(interaction)
            
            # Fallback to memory cache
            elif user_id in self.interactions_cache:
                interactions = self.interactions_cache[user_id][-limit:]
                
            return interactions
            
        except Exception as e:
            logger.error(f"Error getting user interactions: {e}")
            return []
    
    async def analyze_user_preferences(self, user_id: str) -> UserPreferences:
        """Analyze user interactions to determine preferences"""
        try:
            interactions = await self.get_user_interactions(user_id, limit=500)
            
            if not interactions:
                # Return default preferences for new users
                return UserPreferences(
                    preferred_symbols=["AAPL", "TSLA", "MSFT", "GOOGL"],
                    preferred_datasets=["XNAS.ITCH", "XNYS.PILLAR"],
                    preferred_timeframes=["ohlcv-1h", "ohlcv-1d"],
                    favorite_news_categories=["market", "technology"],
                    trading_style="swing_trader",
                    risk_tolerance="medium",
                    active_hours=[9, 10, 11, 14, 15, 16],
                    last_updated=datetime.now()
                )
            
            # Analyze symbol preferences
            symbol_counts = {}
            dataset_counts = {}
            timeframe_counts = {}
            hour_counts = {}
            
            for interaction in interactions:
                # Track active hours
                hour = interaction.timestamp.hour
                hour_counts[hour] = hour_counts.get(hour, 0) + 1
                
                # Track symbols
                if "symbol" in interaction.metadata:
                    symbol = interaction.metadata["symbol"]
                    symbol_counts[symbol] = symbol_counts.get(symbol, 0) + 1
                
                # Track datasets
                if "dataset" in interaction.metadata:
                    dataset = interaction.metadata["dataset"]
                    dataset_counts[dataset] = dataset_counts.get(dataset, 0) + 1
                
                # Track timeframes
                if "timeframe" in interaction.metadata:
                    timeframe = interaction.metadata["timeframe"]
                    timeframe_counts[timeframe] = timeframe_counts.get(timeframe, 0) + 1
            
            # Determine trading style based on timeframe preferences
            trading_style = "swing_trader"  # default
            if timeframe_counts:
                most_used_timeframe = max(timeframe_counts, key=timeframe_counts.get)
                if "1m" in most_used_timeframe or "5m" in most_used_timeframe:
                    trading_style = "day_trader"
                elif "1d" in most_used_timeframe or "1w" in most_used_timeframe:
                    trading_style = "long_term"
            
            # Determine risk tolerance based on interaction patterns
            risk_tolerance = "medium"  # default
            signal_clicks = sum(1 for i in interactions if i.interaction_type == UserInteractionType.SIGNAL_CLICK)
            backtest_runs = sum(1 for i in interactions if i.interaction_type == UserInteractionType.BACKTEST_RUN)
            
            if signal_clicks > backtest_runs * 2:
                risk_tolerance = "high"  # Acts on signals without much backtesting
            elif backtest_runs > signal_clicks:
                risk_tolerance = "low"  # Careful, lots of backtesting
            
            return UserPreferences(
                preferred_symbols=list(sorted(symbol_counts.keys(), key=symbol_counts.get, reverse=True)[:10]),
                preferred_datasets=list(sorted(dataset_counts.keys(), key=dataset_counts.get, reverse=True)[:5]),
                preferred_timeframes=list(sorted(timeframe_counts.keys(), key=timeframe_counts.get, reverse=True)[:5]),
                favorite_news_categories=["market", "technology"],  # Could be enhanced with news click analysis
                trading_style=trading_style,
                risk_tolerance=risk_tolerance,
                active_hours=list(sorted(hour_counts.keys(), key=hour_counts.get, reverse=True)[:6]),
                last_updated=datetime.now()
            )
            
        except Exception as e:
            logger.error(f"Error analyzing user preferences: {e}")
            # Return default preferences on error
            return UserPreferences(
                preferred_symbols=["AAPL", "TSLA", "MSFT", "GOOGL"],
                preferred_datasets=["XNAS.ITCH", "XNYS.PILLAR"],
                preferred_timeframes=["ohlcv-1h", "ohlcv-1d"],
                favorite_news_categories=["market", "technology"],
                trading_style="swing_trader",
                risk_tolerance="medium",
                active_hours=[9, 10, 11, 14, 15, 16],
                last_updated=datetime.now()
            )
    
    async def generate_dashboard_personalization(self, user_id: str) -> DashboardPersonalization:
        """Generate personalized dashboard configuration"""
        try:
            preferences = await self.analyze_user_preferences(user_id)
            
            # Generate priority symbols with market data
            priority_symbols = []
            for symbol in preferences.preferred_symbols[:6]:  # Top 6 symbols
                priority_symbols.append({
                    "symbol": symbol,
                    "dataset": preferences.preferred_datasets[0] if preferences.preferred_datasets else "XNAS.ITCH",
                    "priority": len(preferences.preferred_symbols) - preferences.preferred_symbols.index(symbol)
                })
            
            # Generate relevant news keywords based on symbols and trading style
            news_keywords = preferences.preferred_symbols[:5]  # Use top symbols as keywords
            if preferences.trading_style == "day_trader":
                news_keywords.extend(["earnings", "volatility", "volume", "breakout"])
            elif preferences.trading_style == "long_term":
                news_keywords.extend(["dividend", "growth", "fundamentals", "outlook"])
            else:  # swing_trader
                news_keywords.extend(["technical", "momentum", "support", "resistance"])
            
            # Determine market focus based on datasets and symbols
            market_focus = ["stocks"]  # default
            if any("crypto" in dataset.lower() or "btc" in symbol.lower() or "eth" in symbol.lower() 
                   for dataset in preferences.preferred_datasets 
                   for symbol in preferences.preferred_symbols):
                market_focus.append("crypto")
            
            # Widget priorities based on user behavior
            widget_priorities = {
                "market_status": 10,  # Always high priority
                "portfolio_performance": 9,
                "signals": 8 if preferences.risk_tolerance == "high" else 6,
                "news": 7,
                "backtests": 8 if preferences.risk_tolerance == "low" else 5,
                "quick_actions": 6
            }
            
            return DashboardPersonalization(
                priority_symbols=priority_symbols,
                relevant_news_keywords=news_keywords,
                suggested_timeframes=preferences.preferred_timeframes,
                recommended_strategies=[f"{preferences.trading_style}_strategy"],
                market_focus=market_focus,
                widget_priorities=widget_priorities
            )
            
        except Exception as e:
            logger.error(f"Error generating dashboard personalization: {e}")
            # Return default personalization
            return DashboardPersonalization(
                priority_symbols=[
                    {"symbol": "AAPL", "dataset": "XNAS.ITCH", "priority": 5},
                    {"symbol": "TSLA", "dataset": "XNAS.ITCH", "priority": 4},
                    {"symbol": "MSFT", "dataset": "XNAS.ITCH", "priority": 3}
                ],
                relevant_news_keywords=["AAPL", "TSLA", "MSFT", "market", "technology"],
                suggested_timeframes=["ohlcv-1h", "ohlcv-1d"],
                recommended_strategies=["swing_trader_strategy"],
                market_focus=["stocks"],
                widget_priorities={
                    "market_status": 10,
                    "portfolio_performance": 9,
                    "signals": 7,
                    "news": 7,
                    "backtests": 6,
                    "quick_actions": 6
                }
            )
    
    async def get_personalized_market_data(self, user_id: str) -> Dict[str, Any]:
        """Get personalized market data for dashboard"""
        try:
            personalization = await self.generate_dashboard_personalization(user_id)
            
            # This would integrate with your existing market data service
            # For now, return mock data based on user preferences
            market_data = {
                "priority_indices": [],
                "user_symbols": personalization.priority_symbols,
                "suggested_timeframes": personalization.suggested_timeframes,
                "market_focus": personalization.market_focus
            }
            
            # Add personalized market indices based on focus
            if "stocks" in personalization.market_focus:
                market_data["priority_indices"].extend([
                    {"name": "S&P 500", "value": "4,892.38", "change": "+1.2%", "positive": True},
                    {"name": "NASDAQ", "value": "16,748.24", "change": "+1.8%", "positive": True}
                ])
            
            if "crypto" in personalization.market_focus:
                market_data["priority_indices"].extend([
                    {"name": "BTC/USD", "value": "43,250.00", "change": "+2.1%", "positive": True},
                    {"name": "ETH/USD", "value": "2,650.00", "change": "+1.5%", "positive": True}
                ])
            
            # Always include VIX for risk assessment
            market_data["priority_indices"].append(
                {"name": "VIX", "value": "14.32", "change": "-4.2%", "positive": False}
            )
            
            return market_data
            
        except Exception as e:
            logger.error(f"Error getting personalized market data: {e}")
            return {
                "priority_indices": [
                    {"name": "S&P 500", "value": "4,892.38", "change": "+1.2%", "positive": True},
                    {"name": "NASDAQ", "value": "16,748.24", "change": "+1.8%", "positive": True},
                    {"name": "VIX", "value": "14.32", "change": "-4.2%", "positive": False}
                ],
                "user_symbols": [],
                "suggested_timeframes": ["ohlcv-1h", "ohlcv-1d"],
                "market_focus": ["stocks"]
            }


# Global instance
user_analytics_service = UserAnalyticsService()


async def get_user_analytics_service() -> UserAnalyticsService:
    """Dependency injection for FastAPI"""
    return user_analytics_service
