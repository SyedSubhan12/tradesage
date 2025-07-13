import os
import sys
from datetime import datetime, timedelta
import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import redis

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.services.data_storage import DataStorageService
from app.utils.database import get_db

# --- Database and Redis Connection ---
def get_database_session():
    """Create a new database session."""
    db_gen = get_db()
    return next(db_gen)

def get_redis_client():
    """Create a Redis client from environment variables."""
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    return redis.from_url(redis_url)

# --- Main Test Logic ---
def run_test():
    """Runs the data fetching test."""
    print("--- Starting Data Fetch Test ---")
    db_session = None
    try:
        # 1. Initialize services
        db_session = get_database_session()
        redis_client = get_redis_client()
        data_storage_service = DataStorageService(db=db_session, redis_client=redis_client)

        print("Successfully initialized services.")

        # 2. Fetch available symbols
        print("\nFetching available symbols...")
        symbols = data_storage_service.get_symbols()

        if not symbols:
            print("\n--- !!! No symbols found in the database. !!! ---")
            print("Please ensure that the data ingestion process has run successfully.")
            return

        print(f"Found {len(symbols)} symbols: {symbols}")

        # 3. Fetch data for the first symbol
        test_symbol = symbols[0]
        print(f"\nFetching OHLCV data for symbol: '{test_symbol}'...")

        end_date = datetime.now()
        start_date = end_date - timedelta(days=7)
        timeframe = 'ohlcv-1d' # Daily data

        ohlcv_data = data_storage_service.get_ohlcv_data(
            symbol=test_symbol,
            timeframe=timeframe,
            start_date=start_date,
            end_date=end_date
        )

        # 4. Display results
        if not ohlcv_data.empty:
            print(f"\n--- Successfully fetched data for '{test_symbol}' ---")
            print(ohlcv_data.head())
        else:
            print(f"\n--- !!! No OHLCV data found for '{test_symbol}' in the last 7 days. !!! ---")

    except Exception as e:
        print(f"\n--- An error occurred during the test: {e} ---")
    finally:
        if db_session:
            db_session.close()
        print("\n--- Test Finished ---")

if __name__ == "__main__":
    run_test()
