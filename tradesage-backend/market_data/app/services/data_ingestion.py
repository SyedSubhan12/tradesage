import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Tuple, Set
from sqlalchemy.orm import Session
from ..utils.databento_client import DatabentoClient
from ..models.market_data import Symbol, OHLCVData, TradeData
from ..schemas.market_data import SymbolCreate, OHLCVCreate, TradeCreate
import pandas as pd
from collections import defaultdict, deque
import time
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)

@dataclass
class IngestionMetrics:
    """Metrics for monitoring ingestion performance"""
    symbols_processed: int = 0
    ohlcv_records_ingested: int = 0
    trade_records_ingested: int = 0
    api_calls_made: int = 0
    cache_invalidations: int = 0
    errors_encountered: int = 0
    processing_time: float = 0
    throughput_rps: float = 0

@dataclass
class BatchResult:
    """Result of batch processing operation"""
    success: bool
    records_processed: int
    errors: List[str]
    processing_time: float

class CircuitBreaker:
    """Circuit breaker pattern for API calls"""
    
    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'closed'  # closed, open, half-open
        self.lock = threading.Lock()

    def can_execute(self) -> bool:
        """Check if operation can be executed"""
        with self.lock:
            if self.state == 'closed':
                return True
            elif self.state == 'open':
                if time.time() - self.last_failure_time > self.recovery_timeout:
                    self.state = 'half-open'
                    return True
                return False
            else:  # half-open
                return True

    def record_success(self):
        """Record successful operation"""
        with self.lock:
            self.failure_count = 0
            self.state = 'closed'

    def record_failure(self):
        """Record failed operation"""
        with self.lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            
            if self.failure_count >= self.failure_threshold:
                self.state = 'open'

class DataValidator:
    """High-performance data validation"""
    
    @staticmethod
    def validate_ohlcv_batch(records: List[Dict]) -> Tuple[List[Dict], List[str]]:
        """Validate batch of OHLCV records"""
        valid_records = []
        errors = []
        
        for i, record in enumerate(records):
            validation_errors = DataValidator.validate_ohlcv_record(record)
            
            if not validation_errors:
                valid_records.append(record)
            else:
                errors.extend([f"Record {i}: {error}" for error in validation_errors])
        
        return valid_records, errors

    @staticmethod
    def validate_ohlcv_record(record: Dict) -> List[str]:
        """Validate single OHLCV record"""
        errors = []
        
        # Required fields
        required_fields = ['symbol', 'timestamp', 'open', 'high', 'low', 'close']
        for field in required_fields:
            if field not in record or record[field] is None:
                errors.append(f"Missing required field: {field}")
        
        if errors:  # Skip further validation if required fields are missing
            return errors
        
        try:
            # Price validation
            open_price = float(record['open'])
            high_price = float(record['high'])
            low_price = float(record['low'])
            close_price = float(record['close'])
            
            if high_price < low_price:
                errors.append("High price cannot be less than low price")
            
            if high_price < max(open_price, close_price):
                errors.append("High price cannot be less than open or close price")
            
            if low_price > min(open_price, close_price):
                errors.append("Low price cannot be greater than open or close price")
            
            # Volume validation
            if 'volume' in record and record['volume'] is not None:
                volume = int(record['volume'])
                if volume < 0:
                    errors.append("Volume cannot be negative")
            
            # Reasonable price bounds (basic sanity check)
            for price_field in ['open', 'high', 'low', 'close']:
                price = float(record[price_field])
                if price <= 0:
                    errors.append(f"{price_field} price must be positive")
                elif price > 1000000:  # Arbitrary large number
                    errors.append(f"{price_field} price seems unreasonably high")
            
            # Timestamp validation
            if isinstance(record['timestamp'], str):
                datetime.fromisoformat(record['timestamp'].replace('Z', '+00:00'))
            
        except (ValueError, TypeError) as e:
            errors.append(f"Data type validation error: {e}")
        
        return errors

class ProductionDataIngestionService:
    """Production-grade data ingestion with parallel processing and optimization"""
    
    def __init__(self, databento_client: DatabentoClient, db_manager, redis_service, websocket_manager=None):
        self.databento_client = databento_client
        self.db_manager = db_manager
        self.redis_service = redis_service
        self.websocket_manager = websocket_manager
        
        # Performance settings
        self.max_concurrent_requests = 10
        self.batch_size_symbols = 100
        self.batch_size_ohlcv = 1000
        self.batch_size_trades = 5000
        
        # Circuit breakers for external APIs
        self.databento_breaker = CircuitBreaker(failure_threshold=3, recovery_timeout=120)
        self.db_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
        
        # Thread pool for CPU-intensive operations
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
        # Metrics tracking
        self.metrics = IngestionMetrics()
        self.processing_queue = asyncio.Queue(maxsize=1000)
        
        # Background processing
        self.background_tasks: Set[asyncio.Task] = set()
        
        # Cache invalidation tracking
        self.cache_invalidation_queue = deque(maxlen=1000)

    async def start_background_processing(self):
        """Start background processing tasks"""
        # Start queue processor
        task = asyncio.create_task(self._process_ingestion_queue())
        self.background_tasks.add(task)
        
        # Start cache invalidation processor
        task = asyncio.create_task(self._process_cache_invalidations())
        self.background_tasks.add(task)

    async def stop_background_processing(self):
        """Stop all background processing tasks"""
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.background_tasks, return_exceptions=True)
        self.background_tasks.clear()

    # ----------------------- Enhanced Symbol Ingestion -----------------------

    async def ingest_symbols_parallel(self, datasets: List[str]) -> Dict[str, int]:
        """Ingest symbols for multiple datasets in parallel"""
        start_time = time.time()
        results = {}
        
        logger.info(f"Starting parallel symbol ingestion for {len(datasets)} datasets")
        
        # Create semaphore to limit concurrent API calls
        semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        
        async def process_dataset(dataset: str) -> Tuple[str, int]:
            async with semaphore:
                return dataset, await self.ingest_symbols_optimized(dataset)
        
        # Process datasets in parallel
        tasks = [process_dataset(dataset) for dataset in datasets]
        completed_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        total_ingested = 0
        for result in completed_results:
            if isinstance(result, Exception):
                logger.error(f"Dataset ingestion failed: {result}")
                self.metrics.errors_encountered += 1
            else:
                dataset, count = result
                results[dataset] = count
                total_ingested += count
        
        processing_time = time.time() - start_time
        self.metrics.processing_time += processing_time
        self.metrics.symbols_processed += total_ingested
        
        logger.info(f"Parallel symbol ingestion completed: {total_ingested} symbols in {processing_time:.2f}s")
        return results

    async def ingest_symbols_optimized(self, dataset: str) -> int:
        """Optimized symbol ingestion with caching and validation"""
        if not self.databento_breaker.can_execute():
            logger.warning(f"Circuit breaker open for dataset {dataset}")
            return 0
        
        try:
            # Get symbols from Databento with validation
            symbols = await self._get_validated_symbols(dataset)
            
            if not symbols:
                logger.warning(f"No symbols found for dataset {dataset}")
                return 0
            
            # Process in batches for better database performance
            ingested_count = 0
            
            for i in range(0, len(symbols), self.batch_size_symbols):
                batch = symbols[i:i + self.batch_size_symbols]
                
                try:
                    batch_count = await self._process_symbol_batch(batch, dataset)
                    ingested_count += batch_count
                    
                    # Small delay to prevent overwhelming the database
                    await asyncio.sleep(0.1)
                    
                except Exception as e:
                    logger.error(f"Error processing symbol batch for {dataset}: {e}")
                    self.metrics.errors_encountered += 1
                    continue
            
            self.databento_breaker.record_success()
            return ingested_count
            
        except Exception as e:
            logger.error(f"Error in symbol ingestion for {dataset}: {e}")
            self.databento_breaker.record_failure()
            self.metrics.errors_encountered += 1
            return 0

    async def _get_validated_symbols(self, dataset: str) -> List[str]:
        """Get and validate symbols from Databento"""
        try:
            # Check cache first
            cache_key = f"validated_symbols:{dataset}"
            cached_symbols = await self.redis_service.get_with_l1_fallback(cache_key, 'symbols')
            
            if cached_symbols:
                logger.info(f"Using cached symbols for {dataset}: {len(cached_symbols)} symbols")
                return cached_symbols
            
            # Get symbols from Databento
            symbols = self.databento_client.get_available_symbols(dataset)
            self.metrics.api_calls_made += 1
            
            if symbols:
                # Validate symbols by testing data availability
                validated_symbols = await self._validate_symbol_availability(symbols, dataset)
                
                # Cache validated symbols for 1 hour
                await self.redis_service.set_multi_tier(
                    cache_key, 
                    validated_symbols, 
                    'symbols', 
                    ttl=3600
                )
                
                return validated_symbols
            
            return []
            
        except Exception as e:
            logger.error(f"Error getting validated symbols for {dataset}: {e}")
            return []

    async def _validate_symbol_availability(self, symbols: List[str], dataset: str) -> List[str]:
        """Validate symbol availability by testing recent data"""
        if not symbols:
            return []
        
        # Test in smaller batches
        validated_symbols = []
        test_batch_size = 20
        
        for i in range(0, len(symbols), test_batch_size):
            batch = symbols[i:i + test_batch_size]
            
            try:
                # Test with recent date range
                end_date = datetime.now().date()
                start_date = end_date - timedelta(days=7)
                
                test_data = self.databento_client.get_ohlcv_data(
                    symbols=batch,
                    timeframe='ohlcv-1d',
                    start_date=start_date.strftime('%Y-%m-%d'),
                    end_date=end_date.strftime('%Y-%m-%d'),
                    dataset=dataset
                )
                
                if not test_data.empty:
                    # Get symbols that have data
                    available_symbols = test_data['symbol'].unique().tolist()
                    validated_symbols.extend(available_symbols)
                    logger.debug(f"Validated {len(available_symbols)} symbols from batch")
                
                # Rate limiting
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.warning(f"Symbol validation failed for batch: {e}")
                continue
        
        logger.info(f"Validated {len(validated_symbols)} out of {len(symbols)} symbols for {dataset}")
        return validated_symbols

    async def _process_symbol_batch(self, symbols: List[str], dataset: str) -> int:
        """Process a batch of symbols for database insertion"""
        if not self.db_breaker.can_execute():
            logger.warning("Database circuit breaker open")
            return 0
        
        try:
            async with self.db_manager.get_write_connection() as conn:
                # Check existing symbols to avoid duplicates
                existing_query = """
                    SELECT symbol FROM symbols 
                    WHERE symbol = ANY($1) AND dataset = $2
                """
                
                existing_rows = await conn.fetch(existing_query, symbols, dataset)
                existing_symbols = {row['symbol'] for row in existing_rows}
                
                # Filter out existing symbols
                new_symbols = [s for s in symbols if s not in existing_symbols]
                
                if not new_symbols:
                    return 0
                
                # Bulk insert new symbols
                insert_query = """
                    INSERT INTO symbols (symbol, dataset, description, is_active, created_at, updated_at)
                    VALUES ($1, $2, $3, $4, $5, $6)
                """
                
                current_time = datetime.now(timezone.utc)
                
                await conn.executemany(insert_query, [
                    (symbol, dataset, f"{symbol} from {dataset}", True, current_time, current_time)
                    for symbol in new_symbols
                ])
                
                self.db_breaker.record_success()
                logger.debug(f"Inserted {len(new_symbols)} new symbols for {dataset}")
                
                # Invalidate symbols cache
                await self._invalidate_symbols_cache(dataset)
                
                return len(new_symbols)
                
        except Exception as e:
            logger.error(f"Error processing symbol batch: {e}")
            self.db_breaker.record_failure()
            raise

    # ----------------------- Enhanced OHLCV Ingestion -----------------------

    async def ingest_ohlcv_parallel(self, symbols: List[str], timeframes: List[str], 
                                   start_date: str, end_date: str, dataset: str) -> int:
        """Ingest OHLCV data with parallel processing"""
        start_time = time.time()
        total_ingested = 0
        
        logger.info(f"Starting parallel OHLCV ingestion: {len(symbols)} symbols, {len(timeframes)} timeframes")
        
        # Create processing tasks
        semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        
        async def process_combination(symbol_batch: List[str], timeframe: str) -> int:
            async with semaphore:
                return await self.ingest_ohlcv_batch_optimized(
                    symbol_batch, timeframe, start_date, end_date, dataset
                )
        
        # Create symbol batches
        symbol_batches = [
            symbols[i:i + 20]  # Smaller batches for parallel processing
            for i in range(0, len(symbols), 20)
        ]
        
        # Create tasks for all combinations
        tasks = []
        for symbol_batch in symbol_batches:
            for timeframe in timeframes:
                task = process_combination(symbol_batch, timeframe)
                tasks.append(task)
        
        # Execute tasks in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"OHLCV ingestion task failed: {result}")
                self.metrics.errors_encountered += 1
            else:
                total_ingested += result
        
        processing_time = time.time() - start_time
        self.metrics.processing_time += processing_time
        self.metrics.ohlcv_records_ingested += total_ingested
        
        if total_ingested > 0:
            self.metrics.throughput_rps = total_ingested / processing_time
        
        logger.info(f"Parallel OHLCV ingestion completed: {total_ingested} records in {processing_time:.2f}s "
                   f"({self.metrics.throughput_rps:.0f} records/sec)")
        
        return total_ingested

    async def ingest_ohlcv_batch_optimized(self, symbols: List[str], timeframe: str,
                                         start_date: str, end_date: str, dataset: str) -> int:
        """Optimized OHLCV batch ingestion with validation and caching"""
        if not self.databento_breaker.can_execute():
            return 0
        
        try:
            # Get data from Databento
            df = self.databento_client.get_ohlcv_data(
                symbols=symbols,
                timeframe=timeframe,
                start_date=start_date,
                end_date=end_date,
                dataset=dataset
            )
            
            self.metrics.api_calls_made += 1
            
            if df.empty:
                logger.debug(f"No OHLCV data received for {symbols[:3]}... in {timeframe}")
                return 0
            
            # Process data in background thread for CPU-intensive operations
            loop = asyncio.get_event_loop()
            processed_records = await loop.run_in_executor(
                self.thread_pool,
                self._process_ohlcv_dataframe,
                df, dataset, timeframe
            )
            
            if not processed_records:
                return 0
            
            # Validate records
            valid_records, validation_errors = DataValidator.validate_ohlcv_batch(processed_records)
            
            if validation_errors:
                logger.warning(f"OHLCV validation errors for {timeframe}: {len(validation_errors)} errors")
                # Log first few errors for debugging
                for error in validation_errors[:5]:
                    logger.debug(f"Validation error: {error}")
            
            if not valid_records:
                return 0
            
            # Store in database using optimized bulk insert
            ingested_count = await self._bulk_upsert_ohlcv(valid_records)
            
            # Update cache and notify WebSocket clients
            if ingested_count > 0:
                await self._post_ingestion_processing(symbols, timeframe, df, dataset)
            
            self.databento_breaker.record_success()
            return ingested_count
            
        except Exception as e:
            logger.error(f"Error in OHLCV batch ingestion: {e}")
            self.databento_breaker.record_failure()
            return 0

    def _process_ohlcv_dataframe(self, df: pd.DataFrame, dataset: str, timeframe: str) -> List[Dict]:
        """Process OHLCV DataFrame in background thread"""
        try:
            # Ensure UTC timezone
            if df.index.tz is None:
                df.index = df.index.tz_localize('UTC')
            else:
                df.index = df.index.tz_convert('UTC')
            
            # Convert to records
            records = []
            for idx, row in df.iterrows():
                record = {
                    'symbol': row.get('symbol'),
                    'dataset': dataset,
                    'timeframe': timeframe,
                    'timestamp': idx,
                    'open': row.get('open'),
                    'high': row.get('high'),
                    'low': row.get('low'),
                    'close': row.get('close'),
                    'volume': row.get('volume'),
                    'vwap': row.get('vwap'),
                    'trades_count': row.get('trades_count')
                }
                records.append(record)
            
            return records
            
        except Exception as e:
            logger.error(f"Error processing OHLCV DataFrame: {e}")
            return []

    async def _bulk_upsert_ohlcv(self, records: List[Dict]) -> int:
        """Bulk upsert OHLCV records with optimized performance"""
        if not records:
            return 0
        
        try:
            # Sort records by timestamp for better index performance
            records.sort(key=lambda x: (x['symbol'], x['timestamp']))
            
            # Use the optimized database manager's bulk upsert
            return await self.db_manager.upsert_ohlcv_batch(records)
            
        except Exception as e:
            logger.error(f"Error in bulk OHLCV upsert: {e}")
            raise

    async def _post_ingestion_processing(self, symbols: List[str], timeframe: str, 
                                       df: pd.DataFrame, dataset: str):
        """Post-ingestion processing: cache updates and WebSocket notifications"""
        try:
            # Cache the data for quick retrieval
            for symbol in symbols:
                symbol_df = df[df['symbol'] == symbol] if 'symbol' in df.columns else df
                
                if not symbol_df.empty:
                    await self.redis_service.set_ohlcv_cache(symbol, timeframe, symbol_df, dataset)
                    
                    # Notify WebSocket clients if available
                    if self.websocket_manager:
                        latest_row = symbol_df.iloc[-1]
                        latest_data = {
                            'timestamp': symbol_df.index[-1].isoformat(),
                            'open': float(latest_row.get('open', 0)),
                            'high': float(latest_row.get('high', 0)),
                            'low': float(latest_row.get('low', 0)),
                            'close': float(latest_row.get('close', 0)),
                            'volume': int(latest_row.get('volume', 0))
                        }
                        
                        await self.websocket_manager.broadcast_ohlcv_update(
                            symbol, timeframe, latest_data
                        )
            
            # Schedule cache invalidation
            await self._schedule_cache_invalidation(symbols, timeframe)
            
        except Exception as e:
            logger.error(f"Error in post-ingestion processing: {e}")

    # ----------------------- Cache Management -----------------------

    async def _invalidate_symbols_cache(self, dataset: str = None):
        """Invalidate symbols cache"""
        try:
            pattern = f"symbols:{dataset or '*'}"
            self.cache_invalidation_queue.append({
                'pattern': pattern,
                'timestamp': time.time()
            })
            self.metrics.cache_invalidations += 1
            
        except Exception as e:
            logger.error(f"Error invalidating symbols cache: {e}")

    async def _schedule_cache_invalidation(self, symbols: List[str], timeframe: str):
        """Schedule cache invalidation for OHLCV data"""
        try:
            for symbol in symbols:
                pattern = f"ohlcv:{symbol}:{timeframe}*"
                self.cache_invalidation_queue.append({
                    'pattern': pattern,
                    'timestamp': time.time()
                })
            
            self.metrics.cache_invalidations += len(symbols)
            
        except Exception as e:
            logger.error(f"Error scheduling cache invalidation: {e}")

    async def _process_cache_invalidations(self):
        """Background task to process cache invalidations"""
        while True:
            try:
                if self.cache_invalidation_queue:
                    # Process in batches
                    batch_size = 50
                    batch = []
                    
                    for _ in range(min(batch_size, len(self.cache_invalidation_queue))):
                        if self.cache_invalidation_queue:
                            batch.append(self.cache_invalidation_queue.popleft())
                    
                    if batch:
                        # Group by pattern to avoid duplicate work
                        patterns = set(item['pattern'] for item in batch)
                        
                        for pattern in patterns:
                            await self.redis_service.invalidate_pattern(pattern)
                
                await asyncio.sleep(5)  # Process every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in cache invalidation processor: {e}")
                await asyncio.sleep(10)

    # ----------------------- Background Queue Processing -----------------------

    async def _process_ingestion_queue(self):
        """Background task to process ingestion queue"""
        while True:
            try:
                # Process queued ingestion tasks
                task = await asyncio.wait_for(self.processing_queue.get(), timeout=1.0)
                
                # Execute the task
                await task()
                self.processing_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error in ingestion queue processor: {e}")
                await asyncio.sleep(1)

    # ----------------------- Monitoring and Stats -----------------------

    def get_ingestion_stats(self) -> Dict:
        """Get comprehensive ingestion statistics"""
        return {
            'metrics': {
                'symbols_processed': self.metrics.symbols_processed,
                'ohlcv_records_ingested': self.metrics.ohlcv_records_ingested,
                'trade_records_ingested': self.metrics.trade_records_ingested,
                'api_calls_made': self.metrics.api_calls_made,
                'cache_invalidations': self.metrics.cache_invalidations,
                'errors_encountered': self.metrics.errors_encountered,
                'processing_time': self.metrics.processing_time,
                'throughput_rps': self.metrics.throughput_rps
            },
            'circuit_breakers': {
                'databento': {
                    'state': self.databento_breaker.state,
                    'failure_count': self.databento_breaker.failure_count
                },
                'database': {
                    'state': self.db_breaker.state,
                    'failure_count': self.db_breaker.failure_count
                }
            },
            'queue_sizes': {
                'processing_queue': self.processing_queue.qsize(),
                'cache_invalidation_queue': len(self.cache_invalidation_queue)
            },
            'background_tasks': len(self.background_tasks)
        }

    def reset_metrics(self):
        """Reset ingestion metrics"""
        self.metrics = IngestionMetrics()

# ----------------------- Backward Compatibility -----------------------

class DataIngestionService:
    """Legacy class for backward compatibility"""
    
    def __init__(self, databento_client: DatabentoClient, db: Session):
        self.databento_client = databento_client
        self.db = db
        # Initialize enhanced service with minimal dependencies
        self.enhanced_service = None

    async def ingest_symbols(self, dataset: str) -> int:
        """Legacy symbol ingestion method"""
        try:
            symbols = self.databento_client.get_available_symbols(dataset)
            
            ingested_count = 0
            for symbol in symbols:
                try:
                    existing_symbol = self.db.query(Symbol).filter(
                        Symbol.symbol == symbol,
                        Symbol.dataset == dataset
                    ).first()
                    
                    if not existing_symbol:
                        new_symbol = Symbol(
                            symbol=symbol,
                            dataset=dataset,
                            description=f"{symbol} from {dataset}"
                        )
                        self.db.add(new_symbol)
                        ingested_count += 1
                
                except Exception as e:
                    logger.error(f"Error ingesting symbol {symbol}: {e}")
                    continue
            
            self.db.commit()
            logger.info(f"Ingested {ingested_count} new symbols for {dataset}")
            return ingested_count
            
        except Exception as e:
            logger.error(f"Error in symbol ingestion for {dataset}: {e}")
            self.db.rollback()
            raise