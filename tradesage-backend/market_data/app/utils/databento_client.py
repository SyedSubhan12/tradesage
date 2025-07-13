import databento as db
import asyncio
from datetime import datetime, timedelta
import pandas as pd
from typing import List, Dict, Optional
import logging
from ..dependency import get_db
from .config import settings

logger = logging.getLogger(__name__)

class DatabentoClient:
    def __init__(self, api_key: str):
        self.client = db.Historical(api_key)
    
    def get_available_symbols(self, dataset: str) -> List[str]:
        """Get all available symbols for a dataset using a more reliable approach"""
        try:
            # Method 1: Use Databento's metadata API (recommended)
            try:
                # Get symbols from the metadata endpoint, which is the correct way to list all symbols
                end_date = datetime.now().date()
                start_date = end_date - timedelta(days=365) # Look back a year for active symbols
                
                symbols_df = self.client.metadata.list_symbols(
                    dataset=dataset,
                    start_date=start_date.strftime('%Y-%m-%d'),
                    end_date=end_date.strftime('%Y-%m-%d'),
                )
                if not symbols_df.empty:
                    # The symbols are in the index of the returned DataFrame
                    available_symbols = symbols_df.index.tolist()
                    logger.info(f"Found {len(available_symbols)} symbols using metadata API")
                    return available_symbols
            except Exception as e:
                logger.warning(f"Metadata API failed: {e}, falling back to testing method")
            
            # Method 2: Fallback - Test with a better date range and approach
            popular_symbols = [
                'AAPL', 'MSFT', 'GOOGL', 'AMZN', 'TSLA', 'META', 'NVDA', 'NFLX',
                'ADBE', 'CRM', 'ORCL', 'INTC', 'AMD', 'QCOM', 'AVGO', 'TXN',
                'CSCO', 'PYPL', 'CMCSA', 'PEP', 'COST', 'TMUS', 'CHTR', 'SBUX',
                'INTU', 'AMGN', 'GILD', 'MDLZ', 'ISRG', 'BKNG', 'REGN', 'ADP',
                'VRTX', 'FISV', 'CSX', 'ATVI', 'ILMN', 'BIIB', 'JD', 'NTES',
                'SIRI', 'SWKS', 'SPLK', 'WDAY', 'CDNS', 'SNPS', 'KLAC', 'CTAS'
            ]
            
            # Use a broader, more recent date range
            end_date = datetime.now().date()
            # Go back 30 days to ensure we have trading days
            start_date = end_date - timedelta(days=30)
            
            # Test symbols in batches instead of individually
            batch_size = 10
            available_symbols = []
            
            for i in range(0, len(popular_symbols), batch_size):
                batch = popular_symbols[i:i + batch_size]
                try:
                    test_data = self.client.timeseries.get_range(
                        dataset=dataset,
                        symbols=batch,
                        schema='ohlcv-1d',
                        start=start_date.strftime('%Y-%m-%d'),
                        end=end_date.strftime('%Y-%m-%d'),
                        limit=1  # Just need to confirm data exists
                    )
                    
                    df = test_data.to_df()
                    if not df.empty:
                        # Get unique symbols from the returned data
                        batch_available = df['symbol'].unique().tolist()
                        available_symbols.extend(batch_available)
                        logger.info(f"Batch {i//batch_size + 1}: Found {len(batch_available)} symbols")
                    
                except Exception as e:
                    logger.debug(f"Batch {i//batch_size + 1} failed: {e}")
                    # If batch fails, test individually with even more recent data
                    recent_start = end_date - timedelta(days=7)
                    for symbol in batch:
                        try:
                            test_data = self.client.timeseries.get_range(
                                dataset=dataset,
                                symbols=[symbol],
                                schema='ohlcv-1d',
                                start=recent_start.strftime('%Y-%m-%d'),
                                end=end_date.strftime('%Y-%m-%d'),
                                limit=1
                            )
                            df = test_data.to_df()
                            if not df.empty:
                                available_symbols.append(symbol)
                        except Exception:
                            continue
            
            logger.info(f"Found {len(available_symbols)} available symbols in {dataset}")
            return list(set(available_symbols))  # Remove duplicates
            
        except Exception as e:
            logger.error(f"Error getting symbols for {dataset}: {e}")
            return []
    
    def get_available_symbols_alternative(self, dataset: str) -> List[str]:
        """Alternative method: Use known symbol lists for specific datasets"""
        
        # Define known symbols for different datasets
        dataset_symbols = {
            'XNAS.ITCH': [
                # NASDAQ symbols
                'AAPL', 'MSFT', 'GOOGL', 'GOOG', 'AMZN', 'TSLA', 'META', 'NVDA', 
                'NFLX', 'ADBE', 'CRM', 'ORCL', 'INTC', 'AMD', 'QCOM', 'AVGO'
            ],
            'NASDAQ.ITCH': [
                # Extended NASDAQ list
                'AAPL', 'MSFT', 'GOOGL', 'AMZN', 'TSLA', 'META', 'NVDA', 'NFLX',
                'ADBE', 'CRM', 'ORCL', 'INTC', 'AMD', 'QCOM', 'AVGO', 'TXN',
                'CSCO', 'PYPL', 'CMCSA', 'PEP', 'COST', 'TMUS', 'CHTR', 'SBUX'
            ]
        }
        
        if dataset in dataset_symbols:
            return dataset_symbols[dataset]
        else:
            logger.warning(f"No predefined symbols for dataset {dataset}")
            return []
    
    def validate_symbols(self, symbols: List[str], dataset: str) -> List[str]:
        """Validate that symbols have recent data available"""
        if not symbols:
            return []
        
        try:
            # Use last 5 trading days
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=7)
            
            # Test all symbols at once
            test_data = self.client.timeseries.get_range(
                dataset=dataset,
                symbols=symbols,
                schema='ohlcv-1d',
                start=start_date.strftime('%Y-%m-%d'),
                end=end_date.strftime('%Y-%m-%d'),
                limit=1
            )
            
            df = test_data.to_df()
            if not df.empty:
                valid_symbols = df['symbol'].unique().tolist()
                logger.info(f"Validated {len(valid_symbols)} out of {len(symbols)} symbols")
                return valid_symbols
            else:
                logger.warning("No valid symbols found")
                return []
                
        except Exception as e:
            logger.error(f"Error validating symbols: {e}")
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

# Updated usage
databento = DatabentoClient(api_key=settings.DATABENTO_API_KEY)

# Usage examples:
async def main():
    dataset = 'XNAS.ITCH'
    
    # Method 1: Try to get symbols automatically
    symbols = databento.get_available_symbols(dataset)
    
    # Method 2: If that fails, use predefined list and validate
    if not symbols:
        logger.info("Falling back to predefined symbol list")
        symbols = databento.get_available_symbols_alternative(dataset)
        symbols = databento.validate_symbols(symbols, dataset)
    
    logger.info(f"Final symbol list: {symbols}")
    
    if symbols:
        # Now get actual data
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=30)
        
        df = databento.get_ohlcv_data(
            symbols=symbols[:5],  # Test with first 5 symbols
            timeframe='ohlcv-1d',
            start_date=start_date.strftime('%Y-%m-%d'),
            end_date=end_date.strftime('%Y-%m-%d'),
            dataset=dataset
        )
        
        logger.info(f"Retrieved data shape: {df.shape}")
    
if __name__ == "__main__":
    asyncio.run(main())