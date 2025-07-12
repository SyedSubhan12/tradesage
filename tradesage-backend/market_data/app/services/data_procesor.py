import asyncio
from datetime import datetime, timedelta
import logging
from typing import List
import time

logger = logging.getLogger(__name__)

class DataPipeline:
    def __init__(self, config: Config):
        self.config = config
        self.databento_client = DatabentoClient(config.DATABENTO_API_KEY)
        self.db_manager = DatabaseManager(config)
        
    async def initialize(self):
        """Initialize the pipeline"""
        await self.db_manager.initialize()
        
    async def discover_and_store_symbols(self):
        """Discover all available symbols and store them"""
        logger.info("Starting symbol discovery...")
        
        all_symbols = []
        for dataset in self.config.DATASETS:
            logger.info(f"Discovering symbols for {dataset}")
            symbols = self.databento_client.get_available_symbols(dataset)
            
            symbol_data = [
                {
                    'symbol': symbol,
                    'dataset': dataset,
                    'description': f'{symbol} from {dataset}'
                }
                for symbol in symbols
            ]
            
            all_symbols.extend(symbol_data)
            
        await self.db_manager.insert_symbols(all_symbols)
        logger.info(f"Stored {len(all_symbols)} symbols")
        
    async def fetch_historical_data(self, days_back: int = 30):
        """Fetch historical data for all symbols"""
        logger.info(f"Fetching historical data for last {days_back} days")
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days_back)
        
        for dataset in self.config.DATASETS:
            symbols = await self.db_manager.get_symbols(dataset)
            
            if not symbols:
                logger.warning(f"No symbols found for {dataset}")
                continue
                
            logger.info(f"Fetching data for {len(symbols)} symbols in {dataset}")
            
            # Process symbols in batches
            for i in range(0, len(symbols), self.config.BATCH_SIZE):
                batch_symbols = symbols[i:i + self.config.BATCH_SIZE]
                
                for timeframe in self.config.TIMEFRAMES:
                    try:
                        logger.info(f"Processing {timeframe} for {len(batch_symbols)} symbols")
                        
                        df = self.databento_client.get_ohlcv_data(
                            symbols=batch_symbols,
                            timeframe=timeframe,
                            start_date=start_date.strftime('%Y-%m-%d'),
                            end_date=end_date.strftime('%Y-%m-%d'),
                            dataset=dataset
                        )
                        
                        if not df.empty:
                            # Convert to list of dictionaries for database insertion
                            records = []
                            for idx, row in df.iterrows():
                                records.append({
                                    'symbol': row.get('symbol'),
                                    'dataset': dataset,
                                    'timeframe': timeframe,
                                    'timestamp': idx,
                                    'open': row.get('open'),
                                    'high': row.get('high'),
                                    'low': row.get('low'),
                                    'close': row.get('close'),
                                    'volume': row.get('volume')
                                })
                            
                            await self.db_manager.insert_ohlcv_data(records)
                            logger.info(f"Inserted {len(records)} records for {timeframe}")
                            
                        # Rate limiting
                        await asyncio.sleep(1)
                        
                    except Exception as e:
                        logger.error(f"Error processing {timeframe} for {dataset}: {e}")
                        continue
    
    async def update_latest_data(self):
        """Update with latest data (for real-time updates)"""
        logger.info("Updating latest data...")
        
        end_date = datetime.now()
        start_date = end_date - timedelta(days=1)  # Last day
        
        for dataset in self.config.DATASETS:
            symbols = await self.db_manager.get_symbols(dataset)
            
            if not symbols:
                continue
                
            # Process in smaller batches for real-time updates
            batch_size = min(self.config.BATCH_SIZE, 100)
            
            for i in range(0, len(symbols), batch_size):
                batch_symbols = symbols[i:i + batch_size]
                
                for timeframe in self.config.TIMEFRAMES:
                    try:
                        df = self.databento_client.get_ohlcv_data(
                            symbols=batch_symbols,
                            timeframe=timeframe,
                            start_date=start_date.strftime('%Y-%m-%d'),
                            end_date=end_date.strftime('%Y-%m-%d'),
                            dataset=dataset
                        )
                        
                        if not df.empty:
                            records = []
                            for idx, row in df.iterrows():
                                records.append({
                                    'symbol': row.get('symbol'),
                                    'dataset': dataset,
                                    'timeframe': timeframe,
                                    'timestamp': idx,
                                    'open': row.get('open'),
                                    'high': row.get('high'),
                                    'low': row.get('low'),
                                    'close': row.get('close'),
                                    'volume': row.get('volume')
                                })
                            
                            await self.db_manager.insert_ohlcv_data(records)
                            
                            # Clear related cache entries
                            pattern = f"ohlcv:*:{timeframe}:*"
                            for key in self.db_manager.redis_client.scan_iter(match=pattern):
                                self.db_manager.redis_client.delete(key)
                                
                        await asyncio.sleep(0.5)
                        
                    except Exception as e:
                        logger.error(f"Error updating {timeframe} for {dataset}: {e}")
                        continue
    
    async def run_pipeline(self, historical_days: int = 30):
        """Run the complete data pipeline"""
        logger.info("Starting data pipeline...")
        
        try:
            await self.initialize()
            
            # Step 1: Discover and store symbols
            await self.discover_and_store_symbols()
            
            # Step 2: Fetch historical data
            await self.fetch_historical_data(historical_days)
            
            logger.info("Data pipeline completed successfully")
            
        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            raise
        finally:
            await self.db_manager.close()