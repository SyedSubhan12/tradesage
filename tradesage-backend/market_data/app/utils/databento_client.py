import databento as db
import asyncio
from datetime import datetime, timedelta
import pandas as pd
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)

class DatabentoClient:
    def __init__(self, api_key: str):
        self.client = db.Historical(api_key)
    
    def get_available_symbols(self, dataset: str) -> List[str]:
        """Get all available symbols for a dataset"""
        try:
            # For now, we'll use a predefined list of popular symbols
            # In production, you might want to use symbology API or maintain a master list
            popular_symbols = [
                'AAPL', 'MSFT', 'GOOGL', 'AMZN', 'TSLA', 'META', 'NVDA', 'NFLX',
                'ADBE', 'CRM', 'ORCL', 'INTC', 'AMD', 'QCOM', 'AVGO', 'TXN',
                'CSCO', 'PYPL', 'CMCSA', 'PEP', 'COST', 'TMUS', 'CHTR', 'SBUX',
                'INTU', 'AMGN', 'GILD', 'MDLZ', 'ISRG', 'BKNG', 'REGN', 'ADP',
                'VRTX', 'FISV', 'CSX', 'ATVI', 'ILMN', 'BIIB', 'JD', 'NTES',
                'SIRI', 'SWKS', 'SPLK', 'WDAY', 'CDNS', 'SNPS', 'KLAC', 'CTAS'
            ]
            
            # Test which symbols are available
            available_symbols = []
            for symbol in popular_symbols:
                try:
                    test_data = self.client.timeseries.get_range(
                        dataset=dataset,
                        symbols=[symbol],
                        schema='ohlcv-1d',
                        start='2024-01-01',
                        end='2024-01-02',
                        limit=1
                    )
                    df = test_data.to_df()
                    if len(df) > 0:
                        available_symbols.append(symbol)
                except Exception as e:
                    logger.debug(f"Symbol {symbol} not available: {e}")
                    continue
            
            logger.info(f"Found {len(available_symbols)} available symbols in {dataset}")
            return available_symbols
            
        except Exception as e:
            logger.error(f"Error getting symbols for {dataset}: {e}")
            return []
    
    def get_ohlcv_data(self, symbols: List[str], timeframe: str, start_date: str, end_date: str, dataset: str) -> pd.DataFrame:
        """Get OHLCV data for symbols"""
        try:
            data = self.client.timeseries.get_range(
                dataset=dataset,
                symbols=symbols,
                schema=timeframe,
                start=start_date,
                end=end_date
            )
            
            df = data.to_df()
            if not df.empty:
                df['dataset'] = dataset
                df['timeframe'] = timeframe
                
            return df
            
        except Exception as e:
            logger.error(f"Error fetching OHLCV data: {e}")
            return pd.DataFrame()
