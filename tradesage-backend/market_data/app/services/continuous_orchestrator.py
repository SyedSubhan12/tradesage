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
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from contextlib import asynccontextmanager
from enum import Enum
import schedule
from croniter import croniter

logger = logging.getLogger(__name__)

class IngestionMode(Enum):
    """Ingestion modes for different data retrieval strategies"""
    HISTORICAL_BACKFILL = "historical_backfill"
    INCREMENTAL_UPDATE = "incremental_update"
    REAL_TIME = "real_time"
    MAINTENANCE = "maintenance"

@dataclass
class DatasetConfig:
    """Configuration for dataset ingestion"""
    dataset_code: str
    timeframes: List[str] = field(default_factory=lambda: ['ohlcv-1d'])
    priority: int = 1  # Lower number = higher priority
    update_frequency_minutes: int = 60  # How often to update this dataset
    max_symbols_per_batch: int = 50
    backfill_chunk_days: int = 30  # Days per chunk for historical backfill
    is_active: bool = True
    last_update: Optional[datetime] = None
    backfill_completed: bool = False

@dataclass
class IngestionSchedule:
    """Ingestion schedule configuration"""
    historical_start_date: str = "2010-01-01"
    incremental_update_cron: str = "0 */1 * * *"  # Every hour
    symbol_refresh_cron: str = "0 6 * * *"  # Daily at 6 AM
    maintenance_cron: str = "0 2 * * 0"  # Weekly on Sunday at 2 AM
    max_concurrent_datasets: int = 5
    pause_between_datasets_seconds: int = 30

@dataclass
class IngestionState:
    """Current state of the ingestion process"""
    mode: IngestionMode = IngestionMode.HISTORICAL_BACKFILL
    active_datasets: Set[str] = field(default_factory=set)
    completed_datasets: Set[str] = field(default_factory=set)
    failed_datasets: Set[str] = field(default_factory=set)
    current_date_range: Optional[Tuple[str, str]] = None
    last_health_check: Optional[datetime] = None
    is_running: bool = False
    should_stop: bool = False

class ContinuousDataOrchestrator:
    """
    Orchestrates continuous data ingestion from 2010 to present
    with automatic scheduling and error recovery
    """
    
    def __init__(
        self,
        ingestion_service: 'ProductionDataIngestionService',
        datasets_config: List[DatasetConfig],
        schedule_config: IngestionSchedule = None
    ):
        self.ingestion_service = ingestion_service
        self.datasets_config = {ds.dataset_code: ds for ds in datasets_config}
        self.schedule = schedule_config or IngestionSchedule()
        self.state = IngestionState()
        # Dataset-specific start dates pulled from global settings
        from ..utils.config import get_settings
        settings = get_settings()
        self.dataset_start_dates = settings.DATASET_START_DATES
        
        # Adjust ingestion service settings based on orchestrator config
        if hasattr(self.ingestion_service, 'max_concurrent_requests'):
            self.ingestion_service.max_concurrent_requests = min(
                self.ingestion_service.max_concurrent_requests,
                self.schedule.max_concurrent_datasets + 2  # Allow some buffer
            )
            logger.info(f"Adjusted ingestion service max concurrent requests to {self.ingestion_service.max_concurrent_requests} based on orchestrator config")
        
        # Background task management
        self.orchestrator_task: Optional[asyncio.Task] = None
        self.scheduler_task: Optional[asyncio.Task] = None
        self.health_check_task: Optional[asyncio.Task] = None
        
        # Progress tracking
        self.progress_tracker = defaultdict(dict)
        
        # Metrics
        self.orchestrator_metrics = {
            'total_datasets_processed': 0,
            'historical_backfill_completed': 0,
            'incremental_updates_performed': 0,
            'errors_recovered': 0,
            'uptime_hours': 0,
            'last_successful_run': None
        }
        
        logger.info(f"Initialized orchestrator with {len(self.datasets_config)} datasets")

    async def start_continuous_ingestion(self):
        """Start the continuous data ingestion orchestrator"""
        logger.info("Starting continuous data ingestion process")
        
        self.state.is_running = True
        self.state.should_stop = False
        
        # Start orchestrator tasks
        self.orchestrator_task = asyncio.create_task(self._orchestrator_loop())
        self.scheduler_task = asyncio.create_task(self._scheduler_loop())
        self.health_check_task = asyncio.create_task(self._health_check_loop())
        
        logger.info("All ingestion processes started")

    async def stop_continuous_ingestion(self):
        """Stop the continuous data ingestion orchestrator"""
        logger.info("Stopping continuous data ingestion orchestrator")
        
        self.state.should_stop = True
        
        # Cancel tasks
        for task in [self.orchestrator_task, self.scheduler_task, self.health_check_task]:
            if task and not task.done():
                task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(
            self.orchestrator_task,
            self.scheduler_task, 
            self.health_check_task,
            return_exceptions=True
        )
        
        self.state.is_running = False
        logger.info("Continuous data ingestion stopped")

    async def _orchestrator_loop(self):
        """Main orchestrator loop managing the ingestion process"""
        try:
            # Phase 1: Historical backfill (2010 to yesterday)
            await self._historical_backfill_phase()
            
            # Phase 2: Switch to incremental updates
            self.state.mode = IngestionMode.INCREMENTAL_UPDATE
            
            # Phase 3: Continuous incremental updates
            await self._incremental_update_phase()
            
        except Exception as e:
            logger.error(f"Critical error in orchestrator loop: {e}")
            await self._handle_critical_error(e)

    async def _historical_backfill_phase(self):
        """Phase 1: Historical data backfill from 2010 to yesterday"""
        logger.info("Starting historical backfill from 2010-01-01")
        
        self.state.mode = IngestionMode.HISTORICAL_BACKFILL
        
        # Get yesterday's date as end point
        yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
        
        # First, ingest all symbols for all datasets
        await self._ingest_all_symbols()
        
        # Then backfill historical data for each dataset
        for dataset_code, dataset_config in self.datasets_config.items():
            if not dataset_config.is_active:
                continue
                
            try:
                # Determine real start_date: the first *missing* day after the latest bar
                start_date_cfg = self.dataset_start_dates.get(dataset_code, '2010-01-01')
                # Inspect DB to find latest ingested bar across timeframes
                latest_dates = []
                for tf in dataset_config.timeframes:
                    ts = await self.ingestion_service.get_latest_dataset_ohlcv_date(dataset_code, tf)
                    if ts:
                        latest_dates.append(ts.date())
                if latest_dates:
                    # +1 day after max timestamp present
                    calc_start_dt = max(latest_dates) + timedelta(days=1)
                    start_date = max(calc_start_dt.strftime('%Y-%m-%d'), start_date_cfg)
                else:
                    start_date = start_date_cfg
                # If nothing to backfill, continue
                if datetime.strptime(start_date, '%Y-%m-%d') > datetime.strptime(yesterday, '%Y-%m-%d'):
                    logger.info(f"{dataset_code} already backfilled up to {yesterday}. Skipping historical phase.")
                    dataset_config.backfill_completed = True
                    self.state.completed_datasets.add(dataset_code)
                    continue
                logger.info(f"Starting historical backfill for {dataset_code} ({start_date} to {yesterday})")
                
                # Get symbols using the ingestion service method
                symbols = await self.ingestion_service.get_dataset_symbols(dataset_config.dataset_code)
                if not symbols:
                    logger.warning(f"No symbols available for {dataset_code}, skipping")
                    continue
                
                logger.info(f"Found {len(symbols)} symbols for {dataset_code}")
                
                # Split date range into chunks
                start_dt = datetime.strptime(start_date, '%Y-%m-%d')
                end_dt = datetime.strptime(yesterday, '%Y-%m-%d')
                
                current_dt = start_dt
                total_ingested = 0
                
                while current_dt < end_dt and not self.state.should_stop:
                    chunk_end_dt = min(
                        current_dt + timedelta(days=dataset_config.backfill_chunk_days),
                        end_dt
                    )
                    
                    chunk_start = current_dt.strftime('%Y-%m-%d')
                    chunk_end = chunk_end_dt.strftime('%Y-%m-%d')
                    
                    logger.info(f"Processing {dataset_code} chunk: {chunk_start} to {chunk_end}")
                    
                    try:
                        # Process in symbol batches
                        for i in range(0, len(symbols), dataset_config.max_symbols_per_batch):
                            symbol_batch = symbols[i:i + dataset_config.max_symbols_per_batch]
                            
                            chunk_ingested = await self.ingestion_service.ingest_ohlcv_parallel(
                                symbols=symbol_batch,
                                timeframes=dataset_config.timeframes,
                                start_date=chunk_start,
                                end_date=chunk_end,
                                dataset=dataset_config.dataset_code
                            )
                            
                            total_ingested += chunk_ingested
                            
                            # Brief pause between batches
                            await asyncio.sleep(2)
                        
                        # Update progress
                        progress_pct = ((current_dt - start_dt).days / (end_dt - start_dt).days) * 100
                        self.progress_tracker[dataset_config.dataset_code]['backfill_progress'] = progress_pct
                        
                        logger.info(f"Chunk completed: {chunk_ingested} records. Progress: {progress_pct:.1f}%")
                        
                    except Exception as e:
                        logger.error(f"Error processing chunk {chunk_start}-{chunk_end} for {dataset_code}: {e}")
                        # Continue with next chunk instead of failing entire backfill
                    
                    current_dt = chunk_end_dt
                    
                    # Longer pause between chunks to avoid overwhelming APIs
                    await asyncio.sleep(10)
                
                logger.info(f"Historical backfill completed for {dataset_code}: {total_ingested} total records")
                dataset_config.backfill_completed = True
                self.state.completed_datasets.add(dataset_code)
                self.orchestrator_metrics['historical_backfill_completed'] += 1
                
            except Exception as e:
                logger.error(f"Historical backfill failed for {dataset_code}: {e}")
                self.state.failed_datasets.add(dataset_code)
                continue
        
        logger.info("Historical backfill completed for all datasets")

    async def _incremental_update_phase(self):
        """Phase 2: Continuous incremental updates"""
        logger.info("Switching to incremental update mode")
        
        while not self.state.should_stop:
            try:
                # Update symbols periodically
                if self._should_refresh_symbols():
                    await self._ingest_all_symbols()
                
                # Perform incremental updates for each active dataset
                for dataset_code, dataset_config in self.datasets_config.items():
                    if not dataset_config.is_active or not self._should_update_dataset(dataset_config):
                        continue
                    
                    await self._incremental_update_dataset(dataset_config)
                    dataset_config.last_update = datetime.now(timezone.utc)
                    
                    # Brief pause between datasets
                    await asyncio.sleep(self.schedule.pause_between_datasets_seconds)
                
                self.orchestrator_metrics['incremental_updates_performed'] += 1
                
                # Wait before next cycle
                await asyncio.sleep(300)  # 5 minutes between cycles
                
            except Exception as e:
                logger.error(f"Error in incremental update phase: {e}")
                await self._handle_error_recovery(e)
                await asyncio.sleep(60)  # Wait 1 minute before retry

    async def _ingest_all_symbols(self):
        """Ingest symbols for all active datasets"""
        logger.info("Ingesting symbols for all datasets")
        
        active_datasets = [
            ds.dataset_code for ds in self.datasets_config.values() 
            if ds.is_active
        ]
        
        if not active_datasets:
            logger.warning("No active datasets found")
            return
        
        try:
            results = await self.ingestion_service.ingest_symbols_parallel(active_datasets)
            
            total_symbols = sum(results.values())
            logger.info(f"Symbol ingestion completed: {total_symbols} total symbols across {len(active_datasets)} datasets")
            
            for dataset_code, count in results.items():
                logger.info(f"Dataset {dataset_code}: {count} symbols")
                
        except Exception as e:
            logger.error(f"Error ingesting symbols: {e}")
            raise

    async def _backfill_dataset_historical(self, dataset_config: DatasetConfig, start_date: str, end_date: str):
        """Backfill historical data for a specific dataset"""
        logger.info(f"Starting historical backfill for {dataset_config.dataset_code} ({start_date} to {end_date})")
        
        # FIXED: Get symbols using the ingestion service method
        symbols = await self.ingestion_service.get_dataset_symbols(dataset_config.dataset_code)
        if not symbols:
            logger.warning(f"No symbols available for {dataset_config.dataset_code}, skipping")
            return
        
        logger.info(f"Found {len(symbols)} symbols for {dataset_config.dataset_code}")
        
        # Split date range into chunks
        start_dt = datetime.strptime(start_date, '%Y-%m-%d')
        end_dt = datetime.strptime(end_date, '%Y-%m-%d')
        
        current_dt = start_dt
        total_ingested = 0
        
        while current_dt < end_dt and not self.state.should_stop:
            chunk_end_dt = min(
                current_dt + timedelta(days=dataset_config.backfill_chunk_days),
                end_dt
            )
            
            chunk_start = current_dt.strftime('%Y-%m-%d')
            chunk_end = chunk_end_dt.strftime('%Y-%m-%d')
            
            logger.info(f"Processing {dataset_config.dataset_code} chunk: {chunk_start} to {chunk_end}")
            
            try:
                # Process in symbol batches
                for i in range(0, len(symbols), dataset_config.max_symbols_per_batch):
                    symbol_batch = symbols[i:i + dataset_config.max_symbols_per_batch]
                    
                    chunk_ingested = await self.ingestion_service.ingest_ohlcv_parallel(
                        symbols=symbol_batch,
                        timeframes=dataset_config.timeframes,
                        start_date=chunk_start,
                        end_date=chunk_end,
                        dataset=dataset_config.dataset_code
                    )
                    
                    total_ingested += chunk_ingested
                    
                    # Brief pause between batches
                    await asyncio.sleep(2)
                
                # Update progress
                progress_pct = ((current_dt - start_dt).days / (end_dt - start_dt).days) * 100
                self.progress_tracker[dataset_config.dataset_code]['backfill_progress'] = progress_pct
                
                logger.info(f"Chunk completed: {chunk_ingested} records. Progress: {progress_pct:.1f}%")
                
            except Exception as e:
                logger.error(f"Error processing chunk {chunk_start}-{chunk_end} for {dataset_config.dataset_code}: {e}")
                # Continue with next chunk instead of failing entire backfill
            
            current_dt = chunk_end_dt
            
            # Longer pause between chunks to avoid overwhelming APIs
            await asyncio.sleep(10)
        
        logger.info(f"Historical backfill completed for {dataset_config.dataset_code}: {total_ingested} total records")

    async def _incremental_update_dataset(self, dataset_config: DatasetConfig):
        """Perform incremental update for a dataset (recent data)"""
        logger.debug(f"Performing incremental update for {dataset_config.dataset_code}")
        
        # Get symbols using the ingestion service method
        symbols = await self.ingestion_service.get_dataset_symbols(dataset_config.dataset_code)
        if not symbols:
            return
        
        # Determine the date range that is *not yet* present in the database.
        end_dt = datetime.now(timezone.utc) - timedelta(days=1)
        # Roll back to last weekday (Mon-Fri) if yesterday was weekend
        while end_dt.weekday() >= 5:  # 5 = Saturday, 6 = Sunday
            end_dt -= timedelta(days=1)

        # Compute the earliest date we still need, based on DB contents
        start_dt = None
        for tf in dataset_config.timeframes:
            latest_ts = await self.ingestion_service.get_latest_dataset_ohlcv_date(
                dataset_config.dataset_code, tf
            )
            if latest_ts:
                candidate = latest_ts.date() + timedelta(days=1)
            else:
                candidate = end_dt.date()  # If no data, just pull yesterday
            # Keep the *earliest* candidate across timeframes to ensure all TFs aligned
            start_dt = candidate if start_dt is None else min(start_dt, candidate)

        # Nothing new to fetch
        if start_dt > end_dt.date():
            logger.debug(
                "Dataset %s is already up-to-date through %s", dataset_config.dataset_code, end_dt.date()
            )
            return

        start_date = start_dt.strftime("%Y-%m-%d") if isinstance(start_dt, datetime) else start_dt.strftime("%Y-%m-%d")
        end_date = end_dt.strftime("%Y-%m-%d")
        
        try:
            ingested_count = await self.ingestion_service.ingest_ohlcv_parallel(
                symbols=symbols,
                timeframes=dataset_config.timeframes,
                start_date=start_date,
                end_date=end_date,
                dataset=dataset_config.dataset_code
            )
            
            if ingested_count == 0:
                # If a dataset repeatedly yields no data, deactivate it
                dataset_config.is_active = False
                logger.warning(f"No data ingested for {dataset_config.dataset_code}. Marking dataset as inactive.")
            else:
                logger.debug(f"Incremental update completed for {dataset_config.dataset_code}: {ingested_count} records")
            
        except Exception as e:
            logger.error(f"Incremental update failed for {dataset_config.dataset_code}: {e}")
            raise

    def _should_refresh_symbols(self) -> bool:
        """Check if symbols should be refreshed"""
        if not hasattr(self, '_last_symbol_refresh'):
            self._last_symbol_refresh = datetime.now()
            return True
        
        # Refresh symbols daily
        return (datetime.now() - self._last_symbol_refresh).total_seconds() > 86400

    def _should_update_dataset(self, dataset_config: DatasetConfig) -> bool:
        """Check if dataset should be updated based on frequency"""
        if not dataset_config.last_update:
            return True
        
        time_since_update = (datetime.now(timezone.utc) - dataset_config.last_update).total_seconds()
        return time_since_update >= (dataset_config.update_frequency_minutes * 60)

    async def _scheduler_loop(self):
        """Background scheduler for periodic tasks"""
        while not self.state.should_stop:
            try:
                # Check for scheduled maintenance
                if self._should_run_maintenance():
                    await self._run_maintenance_tasks()
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}")
                await asyncio.sleep(60)

    async def _health_check_loop(self):
        """Background health check and monitoring"""
        while not self.state.should_stop:
            try:
                await self._perform_health_check()
                await self._update_metrics()
                
                self.state.last_health_check = datetime.now(timezone.utc)
                await asyncio.sleep(300)  # Every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in health check: {e}")
                await asyncio.sleep(60)

    async def _perform_health_check(self):
        """Perform health checks on system components"""
        # Check database connectivity
        try:
            async with self.ingestion_service.db_manager.get_read_connection() as conn:
                await conn.fetchval("SELECT 1")
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            raise
        
        # Check Redis connectivity
        try:
            await self.ingestion_service.redis_service.ping()
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            raise
        
        # Check circuit breaker states
        stats = self.ingestion_service.get_ingestion_stats()
        if stats['circuit_breakers']['databento']['state'] == 'open':
            logger.warning("Databento circuit breaker is open")
        
        if stats['circuit_breakers']['database']['state'] == 'open':
            logger.warning("Database circuit breaker is open")

    async def _update_metrics(self):
        """Update orchestrator metrics"""
        # Calculate uptime
        if hasattr(self, '_start_time'):
            uptime_seconds = (datetime.now() - self._start_time).total_seconds()
            self.orchestrator_metrics['uptime_hours'] = uptime_seconds / 3600
        else:
            self._start_time = datetime.now()

    def _should_run_maintenance(self) -> bool:
        """Check if maintenance should be run"""
        # Run maintenance weekly on Sunday at 2 AM
        now = datetime.now()
        return (now.weekday() == 6 and  # Sunday
                now.hour == 2 and 
                getattr(self, '_last_maintenance', datetime.min).date() != now.date())

    async def _run_maintenance_tasks(self):
        """Run periodic maintenance tasks"""
        logger.info("Running maintenance tasks")
        
        try:
            # Reset metrics
            self.ingestion_service.reset_metrics()
            
            # Clean up old cache entries
            await self.ingestion_service.redis_service.cleanup_expired_keys()
            
            # Database maintenance (analyze tables, etc.)
            await self._run_database_maintenance()
            
            self._last_maintenance = datetime.now()
            logger.info("Maintenance tasks completed")
            
        except Exception as e:
            logger.error(f"Error during maintenance: {e}")

    async def _run_database_maintenance(self):
        """Run database maintenance tasks"""
        try:
            async with self.ingestion_service.db_manager.get_write_connection() as conn:
                # Analyze tables for query optimization
                await conn.execute("ANALYZE")
                
                # Clean up old log entries (keep last 30 days)
                cutoff_date = datetime.now() - timedelta(days=30)
                await conn.execute(
                    "DELETE FROM ingestion_logs WHERE created_at < $1",
                    cutoff_date
                )
                
        except Exception as e:
            logger.error(f"Database maintenance failed: {e}")

    async def _handle_critical_error(self, error: Exception):
        """Handle critical errors that might require restart"""
        logger.critical(f"Critical error occurred: {error}")
        
        # Try to recover
        try:
            await self._error_recovery_procedure()
            self.orchestrator_metrics['errors_recovered'] += 1
        except Exception as recovery_error:
            logger.critical(f"Recovery failed: {recovery_error}")
            self.state.should_stop = True

    async def _handle_error_recovery(self, error: Exception):
        """Handle recoverable errors"""
        logger.error(f"Recoverable error: {error}")
        
        # Implement exponential backoff
        backoff_time = min(300, 30 * (self.orchestrator_metrics.get('consecutive_errors', 0) + 1))
        logger.info(f"Waiting {backoff_time} seconds before retry")
        await asyncio.sleep(backoff_time)

    async def _error_recovery_procedure(self):
        """Standard error recovery procedure"""
        logger.info("Starting error recovery procedure")
        
        # Reset circuit breakers if needed
        self.ingestion_service.databento_breaker.record_success()
        self.ingestion_service.db_breaker.record_success()
        
        # Clear any stuck queues
        while not self.ingestion_service.processing_queue.empty():
            try:
                self.ingestion_service.processing_queue.get_nowait()
                self.ingestion_service.processing_queue.task_done()
            except:
                break
        
        logger.info("Error recovery completed")

    def get_orchestrator_status(self) -> Dict:
        """Get comprehensive status of the orchestrator"""
        return {
            'state': {
                'mode': self.state.mode.value,
                'is_running': self.state.is_running,
                'active_datasets': list(self.state.active_datasets),
                'completed_datasets': list(self.state.completed_datasets),
                'failed_datasets': list(self.state.failed_datasets),
                'last_health_check': self.state.last_health_check.isoformat() if self.state.last_health_check else None
            },
            'datasets': {
                code: {
                    'is_active': config.is_active,
                    'last_update': config.last_update.isoformat() if config.last_update else None,
                    'backfill_completed': config.backfill_completed,
                    'timeframes': config.timeframes,
                    'update_frequency_minutes': config.update_frequency_minutes
                }
                for code, config in self.datasets_config.items()
            },
            'progress': dict(self.progress_tracker),
            'metrics': self.orchestrator_metrics,
            'ingestion_stats': self.ingestion_service.get_ingestion_stats()
        }

# Example usage and configuration
def create_default_datasets() -> List[DatasetConfig]:
    """Build dataset configurations from global settings to avoid duplication"""
    from ..utils.config import get_settings
    settings = get_settings()
    return [
        DatasetConfig(
            dataset_code=ds,
            timeframes=settings.TIMEFRAMES,
            priority=1 if idx < 2 else 2,
            update_frequency_minutes=60,
            max_symbols_per_batch=settings.BATCH_SIZE_SYMBOLS
        )
        for idx, ds in enumerate(settings.DATASETS)
    ]