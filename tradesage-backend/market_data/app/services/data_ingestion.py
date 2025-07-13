import asyncio
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from ..utils.databento_client import DatabentoClient
from ..models.market_data import Symbol, OHLCVData, TradeData
from ..schemas.market_data import SymbolCreate, OHLCVCreate, TradeCreate
import pandas as pd

logger = logging.getLogger(__name__)

class DataIngestionService:
    def __init__(self, databento_client: DatabentoClient, db: Session):
        self.databento_client = databento_client
        self.db = db
    
    async def ingest_symbols(self, dataset: str) -> int:
        """Discover and ingest all available symbols for a dataset"""
        try:
            logger.info(f"Starting symbol discovery for {dataset}")
            
            # Get symbols from Databento
            symbols = self.databento_client.get_available_symbols(dataset)
            
            ingested_count = 0
            for symbol in symbols:
                try:
                    # Check if symbol already exists
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
    
    async def ingest_ohlcv_data(self, symbols: List[str], timeframe: str, 
                               start_date: str, end_date: str, dataset: str) -> int:
        """Ingest OHLCV data for given symbols and time range"""
        try:
            logger.info(f"Ingesting {timeframe} data for {len(symbols)} symbols from {start_date} to {end_date}")
            
            # Get data from Databento
            df = self.databento_client.get_ohlcv_data(
                symbols=symbols,
                timeframe=timeframe,
                start_date=start_date,
                end_date=end_date,
                dataset=dataset
            )
            
            if df.empty:
                logger.warning(f"No data received for {symbols} in {timeframe}")
                return 0

            # Ensure timestamp index is timezone-aware (UTC)
            if df.index.tz is None:
                df.index = df.index.tz_localize('UTC')
            else:
                df.index = df.index.tz_convert('UTC')
            
            ingested_count = 0
            batch_size = 1000
            
            # Process data in batches
            for i in range(0, len(df), batch_size):
                batch_df = df.iloc[i:i + batch_size]
                
                batch_records = []
                for idx, row in batch_df.iterrows():
                    record = OHLCVData(
                        symbol=row.get('symbol'),
                        dataset=dataset,
                        timeframe=timeframe,
                        timestamp=idx,
                        open=row.get('open'),
                        high=row.get('high'),
                        low=row.get('low'),
                        close=row.get('close'),
                        volume=row.get('volume'),
                        vwap=row.get('vwap'),
                        trades_count=row.get('trades_count')
                    )
                    batch_records.append(record)
                
                # Bulk insert with upsert logic
                for record in batch_records:
                    existing = self.db.query(OHLCVData).filter(
                        OHLCVData.symbol == record.symbol,
                        OHLCVData.dataset == record.dataset,
                        OHLCVData.timeframe == record.timeframe,
                        OHLCVData.timestamp == record.timestamp
                    ).first()
                    
                    if not existing:
                        self.db.add(record)
                        ingested_count += 1
                    else:
                        # Update existing record
                        existing.open = record.open
                        existing.high = record.high
                        existing.low = record.low
                        existing.close = record.close
                        existing.volume = record.volume
                        existing.vwap = record.vwap
                        existing.trades_count = record.trades_count
                
                self.db.commit()
                logger.info(f"Processed batch {i//batch_size + 1}, records: {len(batch_records)}")
            
            logger.info(f"Successfully ingested {ingested_count} OHLCV records")
            return ingested_count
            
        except Exception as e:
            logger.error(f"Error ingesting OHLCV data: {e}")
            self.db.rollback()
            raise
    
    async def ingest_trade_data(self, symbols: List[str], start_date: str, 
                               end_date: str, dataset: str) -> int:
        """Ingest trade data for given symbols and time range"""
        try:
            logger.info(f"Ingesting trade data for {len(symbols)} symbols from {start_date} to {end_date}")
            
            # Get trade data from Databento
            df = self.databento_client.get_trade_data(
                symbols=symbols,
                start_date=start_date,
                end_date=end_date,
                dataset=dataset
            )
            
            if df.empty:
                logger.warning(f"No trade data received for {symbols}")
                return 0

            # Ensure timestamp index is timezone-aware (UTC)
            if df.index.tz is None:
                df.index = df.index.tz_localize('UTC')
            else:
                df.index = df.index.tz_convert('UTC')
            
            ingested_count = 0
            batch_size = 5000  # Larger batch for trade data
            
            for i in range(0, len(df), batch_size):
                batch_df = df.iloc[i:i + batch_size]
                
                batch_records = []
                for idx, row in batch_df.iterrows():
                    record = TradeData(
                        symbol=row.get('symbol'),
                        dataset=dataset,
                        timestamp=idx,
                        price=row.get('price'),
                        size=row.get('size'),
                        side=row.get('side', 'unknown'),
                        trade_id=row.get('trade_id')
                    )
                    batch_records.append(record)
                
                self.db.bulk_insert_mappings(TradeData, [
                    {
                        'symbol': r.symbol,
                        'dataset': r.dataset,
                        'timestamp': r.timestamp,
                        'price': r.price,
                        'size': r.size,
                        'side': r.side,
                        'trade_id': r.trade_id
                    } for r in batch_records
                ])
                
                ingested_count += len(batch_records)
                self.db.commit()
                
                logger.info(f"Processed trade batch {i//batch_size + 1}, records: {len(batch_records)}")
            
            logger.info(f"Successfully ingested {ingested_count} trade records")
            return ingested_count
            
        except Exception as e:
            logger.error(f"Error ingesting trade data: {e}")
            self.db.rollback()
            raise