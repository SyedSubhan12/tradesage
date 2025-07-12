import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils.config import get_settings
from app.utils.database import get_db
from app.utils.databento_client import DatabentoClient
from app.services.data_ingestion import DataIngestionService
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    """Daily data ingestion script"""
    settings = get_settings()
    databento_client = DatabentoClient(settings.DATABENTO_API_KEY)
    
    # Get database session
    db = next(get_db())
    
    try:
        ingestion_service = DataIngestionService(databento_client, db)
        
        # Step 1: Update symbols for all datasets
        logger.info("Starting symbol discovery...")
        for dataset in settings.DATASETS:
            await ingestion_service.ingest_symbols(dataset)
        
        # Step 2: Ingest latest OHLCV data (last 2 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=2)
        
        logger.info("Starting OHLCV data ingestion...")
        for dataset in settings.DATASETS:
            from app.services.data_storage import DataStorageService
            import redis
            
            redis_client = redis.Redis.from_url(settings.REDIS_URL)
            storage_service = DataStorageService(db, redis_client)
            
            symbols = storage_service.get_symbols(dataset)
            
            if symbols:
                # Process in batches
                batch_size = 50
                for i in range(0, len(symbols), batch_size):
                    batch_symbols = symbols[i:i + batch_size]
                    
                    for timeframe in settings.TIMEFRAMES:
                        await ingestion_service.ingest_ohlcv_data(
                            symbols=batch_symbols,
                            timeframe=timeframe,
                            start_date=start_date.strftime('%Y-%m-%d'),
                            end_date=end_date.strftime('%Y-%m-%d'),
                            dataset=dataset
                        )
                        
                        # Invalidate related cache
                        for symbol in batch_symbols:
                            pattern = f"ohlcv:{symbol}:{timeframe}:*"
                            storage_service.invalidate_cache(pattern)
        
        logger.info("Daily ingestion completed successfully")
        
    except Exception as e:
        logger.error(f"Daily ingestion failed: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(main())