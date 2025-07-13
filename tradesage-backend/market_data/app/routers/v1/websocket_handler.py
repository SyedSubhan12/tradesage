from fastapi import WebSocket, WebSocketDisconnect, HTTPException
from typing import Dict, List, Set, Optional, Any
import json
import asyncio
import logging
import time
from datetime import datetime, timezone
from collections import defaultdict, deque
import uuid
from dataclasses import dataclass, asdict
from enum import Enum
import weakref
import pandas as pd

logger = logging.getLogger(__name__)

class MessageType(Enum):
    """WebSocket message types"""
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    PRICE_UPDATE = "price_update"
    OHLCV_UPDATE = "ohlcv_update"
    TRADE_UPDATE = "trade_update"
    ERROR = "error"
    HEARTBEAT = "heartbeat"
    AUTH = "auth"
    STATUS = "status"

@dataclass
class Subscription:
    """Client subscription information"""
    client_id: str
    symbol: str
    data_type: str  # 'price', 'ohlcv', 'trades'
    timeframe: Optional[str] = None
    params: Optional[Dict] = None
    subscribed_at: float = 0

@dataclass
class ClientInfo:
    """Client connection information"""
    client_id: str
    websocket: WebSocket
    subscriptions: Set[str]  # Set of subscription keys
    connected_at: float
    last_heartbeat: float
    user_id: Optional[str] = None
    rate_limit_count: int = 0
    rate_limit_reset: float = 0

class TradingViewWebSocketManager:
    """High-performance WebSocket manager for real-time trading data"""
    
    def __init__(self, redis_service, data_storage_service):
        self.redis_service = redis_service
        self.data_storage_service = data_storage_service
        
        # Client management
        self.clients: Dict[str, ClientInfo] = {}
        self.subscriptions: Dict[str, Set[str]] = defaultdict(set)  # subscription_key -> client_ids
        
        # Message queues and buffers
        self.message_queue = asyncio.Queue(maxsize=10000)
        self.broadcast_buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Rate limiting
        self.rate_limits = {
            'connections_per_minute': 60,
            'messages_per_minute': 1000,
            'subscriptions_per_client': 50
        }
        
        # Performance metrics
        self.metrics = {
            'total_connections': 0,
            'active_connections': 0,
            'messages_sent': 0,
            'messages_received': 0,
            'broadcasts_sent': 0,
            'errors': 0
        }
        
        # Background tasks
        self.background_tasks: Set[asyncio.Task] = set()
        
        # Start background processors
        asyncio.create_task(self._message_processor())
        asyncio.create_task(self._heartbeat_monitor())
        asyncio.create_task(self._cleanup_inactive_clients())

    async def connect_client(self, websocket: WebSocket, client_id: str = None) -> str:
        """Handle new client connection"""
        try:
            await websocket.accept()
            
            # Generate client ID if not provided
            if not client_id:
                client_id = f"client_{uuid.uuid4().hex[:8]}"
            
            # Check rate limiting
            if not await self._check_connection_rate_limit():
                await websocket.close(code=1008, reason="Connection rate limit exceeded")
                raise HTTPException(status_code=429, detail="Too many connections")
            
            # Create client info
            client_info = ClientInfo(
                client_id=client_id,
                websocket=websocket,
                subscriptions=set(),
                connected_at=time.time(),
                last_heartbeat=time.time()
            )
            
            self.clients[client_id] = client_info
            self.metrics['total_connections'] += 1
            self.metrics['active_connections'] += 1
            
            # Send welcome message
            await self._send_to_client(client_id, {
                'type': MessageType.STATUS.value,
                'status': 'connected',
                'client_id': client_id,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'rate_limits': self.rate_limits
            })
            
            logger.info(f"Client {client_id} connected. Active connections: {self.metrics['active_connections']}")
            return client_id
            
        except Exception as e:
            logger.error(f"Error connecting client: {e}")
            self.metrics['errors'] += 1
            raise

    async def disconnect_client(self, client_id: str, reason: str = "Normal closure"):
        """Handle client disconnection"""
        try:
            if client_id not in self.clients:
                return
            
            client_info = self.clients[client_id]
            
            # Remove all subscriptions
            for subscription_key in client_info.subscriptions.copy():
                await self._remove_subscription(client_id, subscription_key)
            
            # Remove client
            del self.clients[client_id]
            self.metrics['active_connections'] -= 1
            
            logger.info(f"Client {client_id} disconnected: {reason}. Active connections: {self.metrics['active_connections']}")
            
        except Exception as e:
            logger.error(f"Error disconnecting client {client_id}: {e}")

    async def handle_message(self, client_id: str, message: str):
        """Handle incoming WebSocket message"""
        try:
            data = json.loads(message)
            message_type = data.get('type')
            
            self.metrics['messages_received'] += 1
            
            # Check rate limiting
            if not await self._check_message_rate_limit(client_id):
                await self._send_error(client_id, "Rate limit exceeded")
                return
            
            # Update heartbeat
            if client_id in self.clients:
                self.clients[client_id].last_heartbeat = time.time()
            
            # Route message based on type
            if message_type == MessageType.SUBSCRIBE.value:
                await self._handle_subscribe(client_id, data)
            elif message_type == MessageType.UNSUBSCRIBE.value:
                await self._handle_unsubscribe(client_id, data)
            elif message_type == MessageType.HEARTBEAT.value:
                await self._handle_heartbeat(client_id, data)
            elif message_type == MessageType.AUTH.value:
                await self._handle_auth(client_id, data)
            else:
                await self._send_error(client_id, f"Unknown message type: {message_type}")
                
        except json.JSONDecodeError:
            await self._send_error(client_id, "Invalid JSON format")
        except Exception as e:
            logger.error(f"Error handling message from {client_id}: {e}")
            await self._send_error(client_id, "Internal server error")

    async def _handle_subscribe(self, client_id: str, data: Dict):
        """Handle subscription request"""
        try:
            symbol = data.get('symbol')
            data_type = data.get('data_type', 'price')  # 'price', 'ohlcv', 'trades'
            timeframe = data.get('timeframe')
            params = data.get('params', {})
            
            if not symbol:
                await self._send_error(client_id, "Symbol is required for subscription")
                return
            
            # Check subscription limits
            client_info = self.clients.get(client_id)
            if not client_info:
                return
            
            if len(client_info.subscriptions) >= self.rate_limits['subscriptions_per_client']:
                await self._send_error(client_id, "Subscription limit exceeded")
                return
            
            # Create subscription key
            subscription_key = f"{symbol}:{data_type}"
            if timeframe:
                subscription_key += f":{timeframe}"
            
            # Add subscription
            client_info.subscriptions.add(subscription_key)
            self.subscriptions[subscription_key].add(client_id)
            
            # Send current data immediately
            await self._send_current_data(client_id, symbol, data_type, timeframe, params)
            
            # Confirm subscription
            await self._send_to_client(client_id, {
                'type': MessageType.STATUS.value,
                'status': 'subscribed',
                'subscription': {
                    'symbol': symbol,
                    'data_type': data_type,
                    'timeframe': timeframe,
                    'subscription_key': subscription_key
                },
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
            logger.info(f"Client {client_id} subscribed to {subscription_key}")
            
        except Exception as e:
            logger.error(f"Error handling subscription for {client_id}: {e}")
            await self._send_error(client_id, "Subscription failed")

    async def _handle_unsubscribe(self, client_id: str, data: Dict):
        """Handle unsubscription request"""
        try:
            symbol = data.get('symbol')
            data_type = data.get('data_type', 'price')
            timeframe = data.get('timeframe')
            
            subscription_key = f"{symbol}:{data_type}"
            if timeframe:
                subscription_key += f":{timeframe}"
            
            await self._remove_subscription(client_id, subscription_key)
            
            await self._send_to_client(client_id, {
                'type': MessageType.STATUS.value,
                'status': 'unsubscribed',
                'subscription_key': subscription_key,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
            
        except Exception as e:
            logger.error(f"Error handling unsubscription for {client_id}: {e}")

    async def _send_current_data(self, client_id: str, symbol: str, data_type: str, 
                               timeframe: Optional[str], params: Dict):
        """Send current data to newly subscribed client"""
        try:
            if data_type == 'price':
                # Send latest price
                price_data = await self.redis_service.get_real_time_price(symbol)
                if price_data:
                    await self._send_to_client(client_id, {
                        'type': MessageType.PRICE_UPDATE.value,
                        'symbol': symbol,
                        'data': price_data,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    })
                    
            elif data_type == 'ohlcv' and timeframe:
                # Send recent OHLCV data
                limit = params.get('limit', 100)
                df = await self._get_recent_ohlcv(symbol, timeframe, limit)
                
                if not df.empty:
                    ohlcv_data = self._format_ohlcv_for_tradingview(df)
                    await self._send_to_client(client_id, {
                        'type': MessageType.OHLCV_UPDATE.value,
                        'symbol': symbol,
                        'timeframe': timeframe,
                        'data': ohlcv_data,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    })
                    
        except Exception as e:
            logger.error(f"Error sending current data to {client_id}: {e}")

    async def _get_recent_ohlcv(self, symbol: str, timeframe: str, limit: int) -> pd.DataFrame:
        """Get recent OHLCV data from cache or database"""
        try:
            # Try cache first
            df = await self.redis_service.get_ohlcv_cache(symbol, timeframe)
            
            if df is None or df.empty:
                # Fallback to database
                from datetime import timedelta
                end_date = datetime.now(timezone.utc)
                start_date = end_date - timedelta(days=7)  # Last week
                
                df = await self.data_storage_service.get_ohlcv_data(
                    symbol, timeframe, start_date, end_date
                )
            
            if not df.empty and limit:
                df = df.tail(limit)
            
            return df
            
        except Exception as e:
            logger.error(f"Error getting recent OHLCV for {symbol}: {e}")
            return pd.DataFrame()

    def _format_ohlcv_for_tradingview(self, df: pd.DataFrame) -> Dict:
        """Format OHLCV data for TradingView compatibility"""
        try:
            return {
                't': [int(ts.timestamp()) for ts in df.index],
                'o': df['open'].fillna(0).tolist(),
                'h': df['high'].fillna(0).tolist(), 
                'l': df['low'].fillna(0).tolist(),
                'c': df['close'].fillna(0).tolist(),
                'v': df['volume'].fillna(0).astype(int).tolist(),
                's': 'ok'
            }
        except Exception as e:
            logger.error(f"Error formatting OHLCV data: {e}")
            return {'s': 'error', 'errmsg': str(e)}

    # ----------------------- Broadcasting Methods -----------------------

    async def broadcast_price_update(self, symbol: str, price_data: Dict):
        """Broadcast price update to all subscribed clients"""
        try:
            subscription_key = f"{symbol}:price"
            
            if subscription_key in self.subscriptions:
                message = {
                    'type': MessageType.PRICE_UPDATE.value,
                    'symbol': symbol,
                    'data': price_data,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
                await self._broadcast_to_subscribers(subscription_key, message)
                
        except Exception as e:
            logger.error(f"Error broadcasting price update for {symbol}: {e}")

    async def broadcast_ohlcv_update(self, symbol: str, timeframe: str, ohlcv_data: Dict):
        """Broadcast OHLCV update to subscribed clients"""
        try:
            subscription_key = f"{symbol}:ohlcv:{timeframe}"
            
            if subscription_key in self.subscriptions:
                message = {
                    'type': MessageType.OHLCV_UPDATE.value,
                    'symbol': symbol,
                    'timeframe': timeframe,
                    'data': ohlcv_data,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
                await self._broadcast_to_subscribers(subscription_key, message)
                
        except Exception as e:
            logger.error(f"Error broadcasting OHLCV update for {symbol}: {e}")

    async def broadcast_trade_update(self, symbol: str, trade_data: Dict):
        """Broadcast trade update to subscribed clients"""
        try:
            subscription_key = f"{symbol}:trades"
            
            if subscription_key in self.subscriptions:
                message = {
                    'type': MessageType.TRADE_UPDATE.value,
                    'symbol': symbol,
                    'data': trade_data,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
                await self._broadcast_to_subscribers(subscription_key, message)
                
        except Exception as e:
            logger.error(f"Error broadcasting trade update for {symbol}: {e}")

    async def _broadcast_to_subscribers(self, subscription_key: str, message: Dict):
        """Broadcast message to all clients subscribed to a key"""
        if subscription_key not in self.subscriptions:
            return
        
        client_ids = self.subscriptions[subscription_key].copy()
        
        # Add to message queue for processing
        await self.message_queue.put({
            'type': 'broadcast',
            'client_ids': client_ids,
            'message': message,
            'subscription_key': subscription_key
        })

    # ----------------------- Background Tasks -----------------------

    async def _message_processor(self):
        """Background task to process message queue"""
        while True:
            try:
                # Process messages in batches for efficiency
                messages = []
                
                # Collect messages with timeout
                try:
                    message = await asyncio.wait_for(self.message_queue.get(), timeout=0.1)
                    messages.append(message)
                    
                    # Collect additional messages without waiting
                    while not self.message_queue.empty() and len(messages) < 100:
                        try:
                            message = self.message_queue.get_nowait()
                            messages.append(message)
                        except asyncio.QueueEmpty:
                            break
                            
                except asyncio.TimeoutError:
                    continue
                
                # Process collected messages
                for message in messages:
                    if message['type'] == 'broadcast':
                        await self._process_broadcast(message)
                    
                    self.message_queue.task_done()
                    
            except Exception as e:
                logger.error(f"Error in message processor: {e}")
                await asyncio.sleep(1)

    async def _process_broadcast(self, broadcast_message: Dict):
        """Process a broadcast message"""
        try:
            client_ids = broadcast_message['client_ids']
            message = broadcast_message['message']
            subscription_key = broadcast_message['subscription_key']
            
            # Send to all subscribed clients in parallel
            send_tasks = []
            dead_clients = []
            
            for client_id in client_ids:
                if client_id in self.clients:
                    task = self._send_to_client_safe(client_id, message)
                    send_tasks.append((client_id, task))
                else:
                    dead_clients.append(client_id)
            
            # Execute sends in parallel
            if send_tasks:
                results = await asyncio.gather(*[task for _, task in send_tasks], return_exceptions=True)
                
                # Check for failed sends
                for (client_id, _), result in zip(send_tasks, results):
                    if isinstance(result, Exception):
                        dead_clients.append(client_id)
            
            # Clean up dead clients
            for client_id in dead_clients:
                self.subscriptions[subscription_key].discard(client_id)
            
            if dead_clients:
                logger.debug(f"Removed {len(dead_clients)} dead clients from {subscription_key}")
            
            self.metrics['broadcasts_sent'] += 1
            
        except Exception as e:
            logger.error(f"Error processing broadcast: {e}")

    async def _send_to_client_safe(self, client_id: str, message: Dict) -> bool:
        """Safely send message to client with error handling"""
        try:
            return await self._send_to_client(client_id, message)
        except Exception as e:
            logger.debug(f"Failed to send to client {client_id}: {e}")
            return False

    async def _send_to_client(self, client_id: str, message: Dict) -> bool:
        """Send message to specific client"""
        try:
            if client_id not in self.clients:
                return False
            
            client_info = self.clients[client_id]
            websocket = client_info.websocket
            
            message_str = json.dumps(message, default=str)
            await websocket.send_text(message_str)
            
            self.metrics['messages_sent'] += 1
            return True
            
        except Exception as e:
            # Client likely disconnected
            await self.disconnect_client(client_id, f"Send failed: {e}")
            return False

    async def _send_error(self, client_id: str, error_message: str):
        """Send error message to client"""
        await self._send_to_client(client_id, {
            'type': MessageType.ERROR.value,
            'error': error_message,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })

    async def _heartbeat_monitor(self):
        """Monitor client heartbeats and disconnect stale connections"""
        while True:
            try:
                current_time = time.time()
                stale_clients = []
                
                for client_id, client_info in self.clients.items():
                    if current_time - client_info.last_heartbeat > 60:  # 60 seconds timeout
                        stale_clients.append(client_id)
                
                for client_id in stale_clients:
                    await self.disconnect_client(client_id, "Heartbeat timeout")
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in heartbeat monitor: {e}")
                await asyncio.sleep(30)

    async def _cleanup_inactive_clients(self):
        """Periodic cleanup of inactive clients and subscriptions"""
        while True:
            try:
                # Clean up empty subscription sets
                empty_subscriptions = [
                    key for key, clients in self.subscriptions.items() 
                    if not clients
                ]
                
                for key in empty_subscriptions:
                    del self.subscriptions[key]
                
                if empty_subscriptions:
                    logger.debug(f"Cleaned up {len(empty_subscriptions)} empty subscriptions")
                
                await asyncio.sleep(300)  # Clean up every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
                await asyncio.sleep(300)

    # ----------------------- Rate Limiting -----------------------

    async def _check_connection_rate_limit(self) -> bool:
        """Check if connection rate limit is exceeded"""
        # Simple implementation - can be enhanced with Redis-based rate limiting
        return True

    async def _check_message_rate_limit(self, client_id: str) -> bool:
        """Check if message rate limit is exceeded for client"""
        if client_id not in self.clients:
            return False
        
        client_info = self.clients[client_id]
        current_time = time.time()
        
        # Reset rate limit counter every minute
        if current_time - client_info.rate_limit_reset > 60:
            client_info.rate_limit_count = 0
            client_info.rate_limit_reset = current_time
        
        # Check rate limit
        if client_info.rate_limit_count >= self.rate_limits['messages_per_minute']:
            return False
        
        client_info.rate_limit_count += 1
        return True

    # ----------------------- Utility Methods -----------------------

    async def _remove_subscription(self, client_id: str, subscription_key: str):
        """Remove subscription for client"""
        if client_id in self.clients:
            self.clients[client_id].subscriptions.discard(subscription_key)
        
        if subscription_key in self.subscriptions:
            self.subscriptions[subscription_key].discard(client_id)

    async def _handle_heartbeat(self, client_id: str, data: Dict):
        """Handle heartbeat message"""
        await self._send_to_client(client_id, {
            'type': MessageType.HEARTBEAT.value,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })

    async def _handle_auth(self, client_id: str, data: Dict):
        """Handle authentication message"""
        # Placeholder for authentication logic
        token = data.get('token')
        
        if token:  # Add your token validation logic
            if client_id in self.clients:
                self.clients[client_id].user_id = data.get('user_id')
            
            await self._send_to_client(client_id, {
                'type': MessageType.STATUS.value,
                'status': 'authenticated',
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        else:
            await self._send_error(client_id, "Invalid authentication token")

    def get_stats(self) -> Dict:
        """Get WebSocket manager statistics"""
        return {
            'metrics': self.metrics.copy(),
            'active_clients': len(self.clients),
            'active_subscriptions': len(self.subscriptions),
            'total_subscription_entries': sum(len(clients) for clients in self.subscriptions.values()),
            'message_queue_size': self.message_queue.qsize()
        }

    async def shutdown(self):
        """Gracefully shutdown the WebSocket manager"""
        logger.info("Shutting down WebSocket manager...")
        
        # Disconnect all clients
        for client_id in list(self.clients.keys()):
            await self.disconnect_client(client_id, "Server shutdown")
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        logger.info("WebSocket manager shutdown complete")

# ----------------------- Global Instance -----------------------

_websocket_manager = None

def get_websocket_manager(redis_service=None, data_storage_service=None) -> TradingViewWebSocketManager:
    """Get singleton WebSocket manager instance"""
    global _websocket_manager
    if _websocket_manager is None:
        if not redis_service or not data_storage_service:
            raise ValueError("Redis service and data storage service required for initialization")
        _websocket_manager = TradingViewWebSocketManager(redis_service, data_storage_service)
    return _websocket_manager