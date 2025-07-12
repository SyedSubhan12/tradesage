import asyncio
import sys
import os
import argparse
from datetime import datetime, timedelta
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.utils.config import get_settings
from app.utils.database import get_db
from app.utils.databento_client import DatabentoClient
from app.services.data_ingestion import DataIngestionService
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def backfill_historical_data(days_back: int = 30, specific_symbols: list = None):
    """Backfill historical data for specified period"""
    settings = get_settings()
    databento_client = DatabentoClient(settings.DATABENTO_API_KEY)
    db = next(get_db())
    
    try:
        ingestion_service = DataIngestionService(databento_client, db)
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        logger.info(f"Backfilling data from {start_date.date()} to {end_date.date()}")
        
        for dataset in settings.DATASETS:
            logger.info(f"Processing dataset: {dataset}")
            
            # Get symbols to process
            if specific_symbols:
                symbols = specific_symbols
            else:
                from app.services.data_storage import DataStorageService
                import redis
                
                redis_client = redis.Redis.from_url(settings.REDIS_URL)
                storage_service = DataStorageService(db, redis_client)
                symbols = storage_service.get_symbols(dataset)
            
            if not symbols:
                logger.warning(f"No symbols found for {dataset}")
                continue
            
            # Process in batches
            batch_size = 20  # Smaller batches for historical data
            for i in range(0, len(symbols), batch_size):
                batch_symbols = symbols[i:i + batch_size]
                logger.info(f"Processing batch {i//batch_size + 1}: {batch_symbols}")
                
                for timeframe in settings.TIMEFRAMES:
                    try:
                        await ingestion_service.ingest_ohlcv_data(
                            symbols=batch_symbols,
                            timeframe=timeframe,
                            start_date=start_date.strftime('%Y-%m-%d'),
                            end_date=end_date.strftime('%Y-%m-%d'),
                            dataset=dataset
                        )
                        
                        # Add delay to respect API limits
                        await asyncio.sleep(2)
                        
                    except Exception as e:
                        logger.error(f"Error processing {timeframe} for {batch_symbols}: {e}")
                        continue
        
        logger.info("Backfill completed successfully")
        
    except Exception as e:
        logger.error(f"Backfill failed: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Backfill historical market data')
    parser.add_argument('--days', type=int, default=30, help='Number of days to backfill')
    parser.add_argument('--symbols', nargs='+', help='Specific symbols to backfill')
    
    args = parser.parse_args()
    
    asyncio.run(backfill_historical_data(args.days, args.symbols))
