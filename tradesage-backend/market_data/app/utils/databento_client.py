import databento as db
import asyncio
from datetime import datetime, timedelta, timezone
import pandas as pd
from typing import List, Dict, Optional, Tuple
import logging
from .config import get_settings
import time
import requests
from concurrent.futures import ThreadPoolExecutor
import os

logger = logging.getLogger(__name__)

class DatabentoClient:
    """Enhanced Databento client with robust symbol discovery and error handling"""
    
    def __init__(self):
        self.api_key = os.getenv("DATABENTO_API_KEY")
        self.client = None
        self.session = requests.Session()
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Dataset configurations
        self.dataset_configs = {
            'XNAS.ITCH': {
                'name': 'NASDAQ ITCH',
                'description': 'NASDAQ Level 1 Market Data',
                'test_symbols': ['AAPL', 'MSFT', 'GOOGL', 'AMZN', 'TSLA']
            },
            'XNYS.PILLAR': {
                'name': 'NYSE Pillar',
                'description': 'NYSE Level 1 Market Data',
                'test_symbols': ['JPM', 'JNJ', 'PG', 'DIS', 'HD']
            },
            'XASE.PILLAR': {
                'name': 'NYSE American Pillar',
                'description': 'NYSE American Level 1 Market Data',
                'test_symbols': ['GE', 'F', 'T', 'VZ', 'KO']
            },
            'BATS.PITCH': {
                'name': 'CBOE BZX Pitch',
                'description': 'CBOE BZX Level 1 Market Data',
                'test_symbols': ['NVDA', 'AMD', 'INTC', 'QCOM', 'AVGO']
            }
        }
        
        # Fallback symbol lists (for when API discovery fails)
        self.fallback_symbols = {
            'XNAS.ITCH': [
                'AAPL', 'MSFT', 'GOOGL', 'GOOG', 'AMZN', 'TSLA', 'META', 'NVDA',
                'NFLX', 'ADBE', 'CRM', 'ORCL', 'INTC', 'AMD', 'QCOM', 'AVGO',
                'TXN', 'CSCO', 'PYPL', 'CMCSA', 'PEP', 'COST', 'TMUS', 'CHTR',
                'SBUX', 'INTU', 'AMGN', 'GILD', 'MDLZ', 'ISRG', 'BKNG', 'REGN',
                'ADP', 'VRTX', 'FISV', 'CSX', 'ATVI', 'ILMN', 'BIIB', 'JD',
                'NTES', 'SIRI', 'SWKS', 'SPLK', 'WDAY', 'CDNS', 'SNPS', 'KLAC'
            ],
            'XNYS.PILLAR': [
                'JPM', 'JNJ', 'PG', 'UNH', 'DIS', 'HD', 'BAC', 'MA', 'V', 'WMT',
                'CVX', 'LLY', 'PFE', 'TMO', 'ABBV', 'ABT', 'MRK', 'ORCL', 'ACN',
                'NKE', 'DHR', 'VZ', 'ADBE', 'QCOM', 'TXN', 'LIN', 'WFC', 'BMY',
                'PM', 'RTX', 'HON', 'UPS', 'LOW', 'AMGN', 'T', 'SPGI', 'IBM',
                'GS', 'CAT', 'SBUX', 'DE', 'GILD', 'AXP', 'BLK', 'MDT', 'CVS'
            ],
            'XASE.PILLAR': [
                'GE', 'F', 'T', 'VZ', 'KO', 'XOM', 'C', 'INTC', 'PFE', 'BAC'
            ],
            'BATS.PITCH': [
                'NVDA', 'AMD', 'INTC', 'QCOM', 'AVGO', 'TXN', 'MRVL', 'MU',
                'LRCX', 'AMAT', 'KLAC', 'ADI', 'MCHP', 'ON', 'SWKS', 'QRVO'
            ]
        }
        
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Databento client with error handling"""
        try:
            if not self.api_key:
                logger.warning("Databento API key not provided or using placeholder")
                return
            
            self.client = db.Historical(self.api_key)
            logger.info("Databento client initialized successfully")
            
            # Test the connection
            self._test_connection()
            
        except Exception as e:
            logger.error(f"Failed to initialize Databento client: {e}")
            self.client = None

    def _test_connection(self):
        """Test Databento API connection"""
        try:
            if not self.client:
                return False
            
            # Try to get metadata for a known dataset
            metadata = self.client.metadata.list_datasets()
            logger.info(f"Databento connection test successful. Available datasets: {len(metadata)}")
            return True
            
        except Exception as e:
            logger.warning(f"Databento connection test failed: {e}")
            return False

    def get_available_symbols(self, dataset: str) -> List[str]:
        """Enhanced symbol discovery with multiple fallback strategies"""
        logger.info(f"Discovering symbols for dataset: {dataset}")
        
        # Strategy 1: Try Databento metadata API
        symbols = self._get_symbols_from_metadata(dataset)
        if symbols:
            logger.info(f"Found {len(symbols)} symbols using metadata API for {dataset}")
            return symbols
        
        # Strategy 2: Try symbol validation with test data
        symbols = self._get_symbols_from_validation(dataset)
        if symbols:
            logger.info(f"Found {len(symbols)} symbols using validation for {dataset}")
            return symbols
        
        # Strategy 3: Use curated fallback list
        symbols = self._get_fallback_symbols(dataset)
        if symbols:
            logger.info(f"Using {len(symbols)} fallback symbols for {dataset}")
            return symbols
        
        logger.warning(f"No symbols found for dataset {dataset}")
        return []

    def _get_symbols_from_metadata(self, dataset: str) -> List[str]:
        """Try to get symbols using Databento metadata API"""
        try:
            if not self.client:
                return []
            
            # Get recent date range
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=30)
            
            # Try to get symbols from metadata
            symbols_df = self.client.metadata.list_symbols(
                dataset=dataset,
                start_date=start_date.strftime('%Y-%m-%d'),
                end_date=end_date.strftime('%Y-%m-%d'),
            )
            
            if not symbols_df.empty:
                symbols = symbols_df.index.tolist()
                # Filter to reasonable symbols (basic validation)
                valid_symbols = [s for s in symbols if self._is_valid_symbol(s)]
                return valid_symbols[:100]  # Limit to first 100
            
        except Exception as e:
            logger.debug(f"Metadata API failed for {dataset}: {e}")
        
        return []

    def _get_symbols_from_validation(self, dataset: str) -> List[str]:
        """Get symbols by testing with known symbol lists"""
        try:
            if not self.client:
                return []
            
            # Get test symbols for this dataset
            test_symbols = self.dataset_configs.get(dataset, {}).get('test_symbols', [])
            if not test_symbols:
                test_symbols = ['AAPL', 'MSFT', 'GOOGL', 'AMZN', 'TSLA']
            
            # Test with recent data
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=7)
            
            validated_symbols = []
            
            # Test symbols in small batches
            batch_size = 5
            for i in range(0, len(test_symbols), batch_size):
                batch = test_symbols[i:i + batch_size]
                
                try:
                    # Try to get some data for these symbols
                    test_data = self.client.timeseries.get_range(
                        dataset=dataset,
                        symbols=batch,
                        schema='ohlcv-1d',
                        start=start_date.strftime('%Y-%m-%d'),
                        end=end_date.strftime('%Y-%m-%d'),
                        limit=1
                    )
                    
                    df = test_data.to_df()
                    if not df.empty:
                        batch_symbols = df['symbol'].unique().tolist()
                        validated_symbols.extend(batch_symbols)
                        logger.debug(f"Validated symbols: {batch_symbols}")
                    
                    # Rate limiting
                    time.sleep(0.5)
                    
                except Exception as e:
                    logger.debug(f"Validation failed for batch {batch}: {e}")
                    continue
            
            if validated_symbols:
                # Expand the list with similar symbols
                expanded_symbols = self._expand_symbol_list(validated_symbols, dataset)
                return expanded_symbols
            
        except Exception as e:
            logger.debug(f"Symbol validation failed for {dataset}: {e}")
        
        return []

    def _expand_symbol_list(self, known_symbols: List[str], dataset: str) -> List[str]:
        """Expand symbol list based on known working symbols"""
        try:
            # Get fallback symbols and validate them
            fallback = self.fallback_symbols.get(dataset, [])
            
            # Combine known symbols with fallback
            all_symbols = list(set(known_symbols + fallback))
            
            # Try to validate a larger set
            if self.client and len(all_symbols) > len(known_symbols):
                return self._batch_validate_symbols(all_symbols, dataset)
            
            return all_symbols
            
        except Exception as e:
            logger.debug(f"Symbol expansion failed: {e}")
            return known_symbols

    def _batch_validate_symbols(self, symbols: List[str], dataset: str) -> List[str]:
        """Validate symbols in batches"""
        try:
            validated = []
            batch_size = 10
            
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=3)
            
            for i in range(0, len(symbols), batch_size):
                batch = symbols[i:i + batch_size]
                
                try:
                    test_data = self.client.timeseries.get_range(
                        dataset=dataset,
                        symbols=batch,
                        schema='ohlcv-1d',
                        start=start_date.strftime('%Y-%m-%d'),
                        end=end_date.strftime('%Y-%m-%d'),
                        limit=1
                    )
                    
                    df = test_data.to_df()
                    if not df.empty:
                        batch_validated = df['symbol'].unique().tolist()
                        validated.extend(batch_validated)
                    
                    time.sleep(0.3)  # Rate limiting
                    
                except Exception as e:
                    logger.debug(f"Batch validation failed for {batch}: {e}")
                    # Add original batch if validation fails (assume they might work)
                    validated.extend(batch)
            
            return validated
            
        except Exception as e:
            logger.debug(f"Batch validation error: {e}")
            return symbols

    def _get_fallback_symbols(self, dataset: str) -> List[str]:
        """Get curated fallback symbols for dataset"""
        fallback = self.fallback_symbols.get(dataset, [])
        
        if not fallback:
            # Generic fallback if dataset not found
            fallback = [
                'AAPL', 'MSFT', 'GOOGL', 'AMZN', 'TSLA', 'META', 'NVDA', 'NFLX',
                'JPM', 'JNJ', 'PG', 'UNH', 'HD', 'BAC', 'V', 'MA'
            ]
        
        return fallback

    def _is_valid_symbol(self, symbol: str) -> bool:
        """Basic symbol validation"""
        if not symbol or len(symbol) > 10:
            return False
        
        # Check for reasonable symbol format
        if not symbol.isalpha():
            return False
        
        # Filter out some common non-equity symbols
        exclude_patterns = ['INDEX', 'FUTURE', 'OPTION', 'WARRANT']
        if any(pattern in symbol.upper() for pattern in exclude_patterns):
            return False
        
        return True

    def get_ohlcv_data(self, symbols: List[str], timeframe: str, start_date: str, 
                      end_date: str, dataset: str) -> pd.DataFrame:
        """Enhanced OHLCV data retrieval with error handling"""
        try:
            if not self.client:
                logger.error("Databento client not initialized")
                return pd.DataFrame()
            
            if not symbols:
                logger.warning("No symbols provided for OHLCV data")
                return pd.DataFrame()
            
            logger.debug(f"Fetching OHLCV data: {len(symbols)} symbols, {timeframe}, {start_date} to {end_date}")
            
            # Limit symbols to prevent API overload
            if len(symbols) > 50:
                symbols = symbols[:50]
                logger.warning(f"Limited symbol request to 50 symbols")
            
            # Get data with retries
            for attempt in range(3):
                try:
                    data = self.client.timeseries.get_range(
                        dataset=dataset,
                        symbols=symbols,
                        schema=timeframe,
                        start=start_date,
                        end=end_date,
                        limit=10000  # Reasonable limit
                    )
                    
                    df = data.to_df()
                    
                    if not df.empty:
                        # Add metadata columns
                        df['dataset'] = dataset
                        df['timeframe'] = timeframe
                        
                        # Ensure proper data types
                        numeric_columns = ['open', 'high', 'low', 'close', 'volume']
                        for col in numeric_columns:
                            if col in df.columns:
                                df[col] = pd.to_numeric(df[col], errors='coerce')
                        
                        logger.info(f"Retrieved {len(df)} OHLCV records for {len(symbols)} symbols")
                        return df
                    else:
                        logger.warning(f"No data returned for symbols: {symbols[:5]}...")
                    
                    break
                    
                except Exception as e:
                    logger.warning(f"OHLCV fetch attempt {attempt + 1} failed: {e}")
                    if attempt < 2:
                        time.sleep(2 ** attempt)  # Exponential backoff
                    else:
                        raise
            
            return pd.DataFrame()
            
        except Exception as e:
            logger.error(f"Error fetching OHLCV data: {e}")
            return pd.DataFrame()

    def get_trade_data(self, symbols: List[str], start_date: str, end_date: str, 
                      dataset: str) -> pd.DataFrame:
        """Get trade data with error handling"""
        try:
            if not self.client:
                logger.error("Databento client not initialized")
                return pd.DataFrame()
            
            logger.debug(f"Fetching trade data: {len(symbols)} symbols, {start_date} to {end_date}")
            
            # Limit symbols and time range for trade data
            if len(symbols) > 10:
                symbols = symbols[:10]
                logger.warning("Limited trade data request to 10 symbols")
            
            data = self.client.timeseries.get_range(
                dataset=dataset,
                symbols=symbols,
                schema='trades',
                start=start_date,
                end=end_date,
                limit=50000  # Trade data can be very large
            )
            
            df = data.to_df()
            
            if not df.empty:
                df['dataset'] = dataset
                logger.info(f"Retrieved {len(df)} trade records")
            
            return df
            
        except Exception as e:
            logger.error(f"Error fetching trade data: {e}")
            return pd.DataFrame()

    def test_dataset_access(self, dataset: str) -> Dict[str, any]:
        """Test access to a specific dataset"""
        try:
            test_result = {
                'dataset': dataset,
                'accessible': False,
                'test_symbols_found': [],
                'error': None,
                'metadata': {}
            }
            
            if not self.client:
                test_result['error'] = "Client not initialized"
                return test_result
            
            # Test with a few known symbols
            test_symbols = self.dataset_configs.get(dataset, {}).get('test_symbols', ['AAPL'])
            
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=2)
            
            try:
                test_data = self.client.timeseries.get_range(
                    dataset=dataset,
                    symbols=test_symbols[:3],  # Test with first 3 symbols
                    schema='ohlcv-1d',
                    start=start_date.strftime('%Y-%m-%d'),
                    end=end_date.strftime('%Y-%m-%d'),
                    limit=10
                )
                
                df = test_data.to_df()
                
                if not df.empty:
                    test_result['accessible'] = True
                    test_result['test_symbols_found'] = df['symbol'].unique().tolist()
                    test_result['metadata'] = {
                        'records_found': len(df),
                        'date_range': f"{start_date} to {end_date}",
                        'schemas_available': ['ohlcv-1d']  # Could expand this
                    }
                else:
                    test_result['error'] = "No data returned for test symbols"
                
            except Exception as e:
                test_result['error'] = str(e)
            
            return test_result
            
        except Exception as e:
            return {
                'dataset': dataset,
                'accessible': False,
                'error': f"Test failed: {str(e)}"
            }

    def get_client_info(self) -> Dict[str, any]:
        """Get information about the Databento client status"""
        info = {
            'initialized': self.client is not None,
            'api_key_provided': bool(self.api_key and self.api_key != 'your-api-key-here'),
            'supported_datasets': list(self.dataset_configs.keys()),
            'connection_tested': False
        }
        
        if self.client:
            info['connection_tested'] = self._test_connection()
        
        return info

# Standalone testing function
async def test_databento_setup():
    """Test function to verify Databento setup"""
    settings = get_settings()
    client = DatabentoClient(settings.DATABENTO_API_KEY)
    
    print("=" * 60)
    print("DATABENTO CLIENT TEST")
    print("=" * 60)
    
    # Test client info
    info = client.get_client_info()
    print(f"Client initialized: {info['initialized']}")
    print(f"API key provided: {info['api_key_provided']}")
    print(f"Connection tested: {info['connection_tested']}")
    
    # Test each dataset
    for dataset in settings.DATASETS:
        print(f"\nTesting dataset: {dataset}")
        print("-" * 40)
        
        test_result = client.test_dataset_access(dataset)
        print(f"Accessible: {test_result['accessible']}")
        
        if test_result['accessible']:
            print(f"Test symbols found: {test_result['test_symbols_found']}")
            print(f"Records: {test_result['metadata'].get('records_found', 0)}")
        else:
            print(f"Error: {test_result['error']}")
        
        # Test symbol discovery
        symbols = client.get_available_symbols(dataset)
        print(f"Symbols discovered: {len(symbols)}")
        if symbols:
            print(f"Sample symbols: {symbols[:10]}")

if __name__ == "__main__":
    asyncio.run(test_databento_setup())