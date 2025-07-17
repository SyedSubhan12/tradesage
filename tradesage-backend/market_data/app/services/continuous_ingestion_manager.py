import asyncio
import logging
from typing import List, Dict, Any

from fastapi import FastAPI

from .data_ingestion import ProductionDataIngestionService
from .continuous_orchestrator import ContinuousDataOrchestrator, DatasetConfig, IngestionSchedule

# Setup logging
logger = logging.getLogger(__name__)

class ContinuousIngestionManager:
    """Manager class to set up and run continuous data ingestion"""
    
    def __init__(self, ingestion_service: ProductionDataIngestionService):
        self.ingestion_service = ingestion_service
        self.orchestrator = None
        self.is_running = False
    
    async def initialize_services(self):
        """Initialize all required services"""
        logger.info("Services initialized successfully")
    
    def create_dataset_configurations(self) -> List[DatasetConfig]:
        """Create dataset configurations pulled from central settings"""
        from ..utils.config import get_settings
        settings = get_settings()

        dataset_configs: List[DatasetConfig] = []
        default_timeframes = settings.TIMEFRAMES

        for idx, ds in enumerate(settings.DATASETS):
            dataset_configs.append(
                DatasetConfig(
                    dataset_code=ds,
                    timeframes=default_timeframes,
                    priority=1 if idx < 2 else 2,  # Simple heuristic: first 2 datasets high priority
                    update_frequency_minutes=30,
                    max_symbols_per_batch=settings.BATCH_SIZE_SYMBOLS,
                    backfill_chunk_days=30,
                    is_active=True,
                )
            )
        return dataset_configs
    
    def create_schedule_configuration(self) -> IngestionSchedule:
        """Create schedule configuration"""
        from ..utils.config import get_settings
        settings = get_settings()

        return IngestionSchedule(
            historical_start_date=settings.HISTORICAL_START_DATE,  
            incremental_update_cron=settings.INCREMENTAL_UPDATE_CRON,  
            symbol_refresh_cron=settings.SYMBOL_REFRESH_CRON,  
            maintenance_cron=settings.MAINTENANCE_CRON,  
            max_concurrent_datasets=settings.MAX_CONCURRENT_DATASETS,  
            pause_between_datasets_seconds=settings.PAUSE_BETWEEN_DATASETS_SECONDS  
        )
    
    async def start_ingestion(self):
        """Start the continuous data ingestion process"""
        try:
            # Initialize services
            await self.initialize_services()
            
            # Create configurations
            datasets = self.create_dataset_configurations()
            schedule = self.create_schedule_configuration()
            
            # Create orchestrator
            self.orchestrator = ContinuousDataOrchestrator(
                ingestion_service=self.ingestion_service,
                datasets_config=datasets,
                schedule_config=schedule
            )
            
            # Start continuous ingestion
            logger.info("Starting continuous data ingestion from 2010 to present...")
            await self.orchestrator.start_continuous_ingestion()
            
            self.is_running = True
            logger.info("Continuous data ingestion started successfully!")
            
            # Monitor the process
            await self._monitor_process()
        except Exception as e:
            logger.error(f"Failed to start ingestion: {e}")
            raise
    
    async def stop_ingestion(self):
        """Stop the continuous data ingestion process"""
        if self.orchestrator and self.is_running:
            logger.info("Stopping continuous data ingestion...")
            await self.orchestrator.stop_continuous_ingestion()
            self.is_running = False
            logger.info("Continuous data ingestion stopped")
    
    async def _monitor_process(self):
        """Monitor the ingestion process and log status"""
        while self.is_running:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                
                # Get status
                status = self.orchestrator.get_orchestrator_status()
                
                # Log key metrics
                state = status['state']
                metrics = status['metrics']
                
                logger.info(f"""
=== Ingestion Status Report ===
Mode: {state['mode']}
Running: {state['is_running']}
Active Datasets: {len(state['active_datasets'])}
Completed Datasets: {len(state['completed_datasets'])}
Failed Datasets: {len(state['failed_datasets'])}

Total Records Ingested: {metrics.get('total_datasets_processed', 0)}
Historical Backfills Completed: {metrics.get('historical_backfill_completed', 0)}
Incremental Updates: {metrics.get('incremental_updates_performed', 0)}
Uptime Hours: {metrics.get('uptime_hours', 0):.1f}

Ingestion Stats:
- OHLCV Records: {status['ingestion_stats']['metrics']['ohlcv_records_ingested']}
- API Calls Made: {status['ingestion_stats']['metrics']['api_calls_made']}
- Errors: {status['ingestion_stats']['metrics']['errors_encountered']}
- Throughput: {status['ingestion_stats']['metrics']['throughput_rps']:.0f} records/sec
================================
                """)
                
                # Check for failures and alert
                if state['failed_datasets']:
                    logger.warning(f"Failed datasets detected: {state['failed_datasets']}")
                
                # Check circuit breaker status
                cb_status = status['ingestion_stats']['circuit_breakers']
                if cb_status['databento']['state'] != 'closed':
                    logger.warning(f"Databento circuit breaker state: {cb_status['databento']['state']}")
                
                if cb_status['database']['state'] != 'closed':
                    logger.warning(f"Database circuit breaker state: {cb_status['database']['state']}")
            except Exception as e:
                logger.error(f"Error in monitoring: {e}")
                await asyncio.sleep(60)
    
    async def get_status(self) -> dict:
        """Get current status of the ingestion process"""
        if self.orchestrator:
            return self.orchestrator.get_orchestrator_status()
        return {"status": "not_initialized"}

# API endpoint setup for FastAPI integration
def setup_ingestion_api(app: FastAPI, manager: 'ContinuousIngestionManager'):
    """Set up FastAPI endpoints for ingestion control and monitoring"""
    from fastapi import Response, status
    
    @app.get("/ingestion/status")
    async def get_ingestion_status():
        """Get current ingestion status"""
        return await manager.get_status()
    
    @app.post("/ingestion/start")
    async def start_ingestion(response: Response):
        """Start data ingestion"""
        if not manager.is_running:
            await manager.start_ingestion()
            response.status_code = status.HTTP_200_OK
            return {"status": "started"}
        return {"status": "already_running"}
    
    @app.post("/ingestion/stop")
    async def stop_ingestion(response: Response):
        """Stop data ingestion"""
        if manager.is_running:
            await manager.stop_ingestion()
            response.status_code = status.HTTP_200_OK
            return {"status": "stopped"}
        return {"status": "not_running"}
