"""
Analytics API endpoints for user behavior tracking and personalized dashboard content
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Dict, Any, Optional
from datetime import datetime
import logging

from ..services.user_analytics import (
    UserAnalyticsService, 
    UserInteraction, 
    UserInteractionType,
    get_user_analytics_service
)
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/analytics", tags=["analytics"])


class InteractionRequest(BaseModel):
    """Request model for tracking user interactions"""
    interaction_type: str
    metadata: Dict[str, Any] = {}
    session_id: Optional[str] = None


class DashboardPersonalizationResponse(BaseModel):
    """Response model for dashboard personalization"""
    priority_symbols: list
    relevant_news_keywords: list
    suggested_timeframes: list
    recommended_strategies: list
    market_focus: list
    widget_priorities: Dict[str, int]


@router.post("/track")
async def track_user_interaction(
    interaction_request: InteractionRequest,
    request: Request,
    analytics_service: UserAnalyticsService = Depends(get_user_analytics_service)
):
    """Track a user interaction for analytics"""
    try:
        # Extract user ID from request (you might get this from JWT token, session, etc.)
        # For now, using a default user ID or IP-based identification
        user_id = request.headers.get("X-User-ID", "default_user")
        
        # Create interaction object
        interaction = UserInteraction(
            user_id=user_id,
            interaction_type=UserInteractionType(interaction_request.interaction_type),
            timestamp=datetime.now(),
            metadata=interaction_request.metadata,
            session_id=interaction_request.session_id
        )
        
        # Track the interaction
        await analytics_service.track_interaction(interaction)
        
        return {"status": "success", "message": "Interaction tracked"}
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid interaction type: {e}")
    except Exception as e:
        logger.error(f"Error tracking interaction: {e}")
        raise HTTPException(status_code=500, detail="Failed to track interaction")


@router.get("/dashboard/personalization")
async def get_dashboard_personalization(
    request: Request,
    analytics_service: UserAnalyticsService = Depends(get_user_analytics_service)
) -> DashboardPersonalizationResponse:
    """Get personalized dashboard configuration for the user"""
    try:
        # Extract user ID from request
        user_id = request.headers.get("X-User-ID", "default_user")
        
        # Generate personalization
        personalization = await analytics_service.generate_dashboard_personalization(user_id)
        
        return DashboardPersonalizationResponse(
            priority_symbols=personalization.priority_symbols,
            relevant_news_keywords=personalization.relevant_news_keywords,
            suggested_timeframes=personalization.suggested_timeframes,
            recommended_strategies=personalization.recommended_strategies,
            market_focus=personalization.market_focus,
            widget_priorities=personalization.widget_priorities
        )
        
    except Exception as e:
        logger.error(f"Error getting dashboard personalization: {e}")
        raise HTTPException(status_code=500, detail="Failed to get personalization")


@router.get("/dashboard/market-data")
async def get_personalized_market_data(
    request: Request,
    analytics_service: UserAnalyticsService = Depends(get_user_analytics_service)
) -> Dict[str, Any]:
    """Get personalized market data for the dashboard"""
    try:
        # Extract user ID from request
        user_id = request.headers.get("X-User-ID", "default_user")
        
        # Get personalized market data
        market_data = await analytics_service.get_personalized_market_data(user_id)
        
        return market_data
        
    except Exception as e:
        logger.error(f"Error getting personalized market data: {e}")
        raise HTTPException(status_code=500, detail="Failed to get market data")


@router.get("/user/preferences")
async def get_user_preferences(
    request: Request,
    analytics_service: UserAnalyticsService = Depends(get_user_analytics_service)
):
    """Get user preferences based on analytics"""
    try:
        # Extract user ID from request
        user_id = request.headers.get("X-User-ID", "default_user")
        
        # Get user preferences
        preferences = await analytics_service.analyze_user_preferences(user_id)
        
        return {
            "preferred_symbols": preferences.preferred_symbols,
            "preferred_datasets": preferences.preferred_datasets,
            "preferred_timeframes": preferences.preferred_timeframes,
            "favorite_news_categories": preferences.favorite_news_categories,
            "trading_style": preferences.trading_style,
            "risk_tolerance": preferences.risk_tolerance,
            "active_hours": preferences.active_hours,
            "last_updated": preferences.last_updated.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting user preferences: {e}")
        raise HTTPException(status_code=500, detail="Failed to get preferences")


@router.get("/user/interactions")
async def get_user_interactions(
    request: Request,
    limit: int = 50,
    analytics_service: UserAnalyticsService = Depends(get_user_analytics_service)
):
    """Get recent user interactions"""
    try:
        # Extract user ID from request
        user_id = request.headers.get("X-User-ID", "default_user")
        
        # Get interactions
        interactions = await analytics_service.get_user_interactions(user_id, limit)
        
        return {
            "interactions": [
                {
                    "type": interaction.interaction_type.value,
                    "timestamp": interaction.timestamp.isoformat(),
                    "metadata": interaction.metadata,
                    "session_id": interaction.session_id
                }
                for interaction in interactions
            ]
        }
        
    except Exception as e:
        logger.error(f"Error getting user interactions: {e}")
        raise HTTPException(status_code=500, detail="Failed to get interactions")


@router.post("/simulate-activity")
async def simulate_user_activity(
    request: Request,
    analytics_service: UserAnalyticsService = Depends(get_user_analytics_service)
):
    """Simulate user activity for testing purposes"""
    try:
        user_id = request.headers.get("X-User-ID", "default_user")
        
        # Simulate various user interactions
        sample_interactions = [
            UserInteraction(
                user_id=user_id,
                interaction_type=UserInteractionType.SYMBOL_VIEW,
                timestamp=datetime.now(),
                metadata={"symbol": "AAPL", "dataset": "XNAS.ITCH"}
            ),
            UserInteraction(
                user_id=user_id,
                interaction_type=UserInteractionType.CHART_VIEW,
                timestamp=datetime.now(),
                metadata={"symbol": "TSLA", "timeframe": "ohlcv-1h"}
            ),
            UserInteraction(
                user_id=user_id,
                interaction_type=UserInteractionType.TIMEFRAME_CHANGE,
                timestamp=datetime.now(),
                metadata={"from_timeframe": "ohlcv-1d", "to_timeframe": "ohlcv-1h"}
            ),
            UserInteraction(
                user_id=user_id,
                interaction_type=UserInteractionType.SIGNAL_CLICK,
                timestamp=datetime.now(),
                metadata={"signal_id": "123", "asset": "AAPL", "type": "BUY"}
            ),
            UserInteraction(
                user_id=user_id,
                interaction_type=UserInteractionType.NEWS_CLICK,
                timestamp=datetime.now(),
                metadata={"headline": "Fed signals rate cut", "category": "market"}
            )
        ]
        
        # Track all sample interactions
        for interaction in sample_interactions:
            await analytics_service.track_interaction(interaction)
        
        return {"status": "success", "message": f"Simulated {len(sample_interactions)} interactions"}
        
    except Exception as e:
        logger.error(f"Error simulating user activity: {e}")
        raise HTTPException(status_code=500, detail="Failed to simulate activity")
