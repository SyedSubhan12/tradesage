"""
Database optimization utilities for TradeSage market data service.
This module provides functions to create indexes and optimize database performance.
"""

import asyncio
import logging
from typing import List, Dict, Any
from .database import get_db_manager

logger = logging.getLogger(__name__)

class DatabaseOptimizer:
    """Handles database optimization tasks including index creation and performance tuning."""
    
    def __init__(self):
        self.db_manager = get_db_manager()
    
    async def create_performance_indexes(self) -> Dict[str, Any]:
        """Create indexes to improve query performance for OHLCV data retrieval."""
        results = {
            'created_indexes': [],
            'failed_indexes': [],
            'existing_indexes': []
        }
        
        # Define indexes for optimal performance
        indexes = [
            {
                'name': 'idx_ohlcv_symbol_timeframe_timestamp',
                'table': 'ohlcv_data',
                'columns': '(symbol_id, timeframe, timestamp DESC)',
                'description': 'Composite index for symbol + timeframe + timestamp queries'
            },
            {
                'name': 'idx_ohlcv_timestamp_desc',
                'table': 'ohlcv_data', 
                'columns': '(timestamp DESC)',
                'description': 'Descending timestamp index for MAX() queries'
            },
            {
                'name': 'idx_symbols_dataset_symbol',
                'table': 'symbols',
                'columns': '(dataset, symbol)',
                'description': 'Composite index for dataset + symbol lookups'
            },
            {
                'name': 'idx_symbols_dataset',
                'table': 'symbols',
                'columns': '(dataset)',
                'description': 'Dataset index for filtering symbols by dataset'
            },
            {
                'name': 'idx_ohlcv_symbol_timestamp',
                'table': 'ohlcv_data',
                'columns': '(symbol_id, timestamp DESC)',
                'description': 'Symbol + timestamp index for time-series queries'
            }
        ]
        
        async with self.db_manager.get_write_connection() as conn:
            for index in indexes:
                try:
                    # Check if index already exists
                    check_sql = """
                        SELECT indexname FROM pg_indexes 
                        WHERE tablename = $1 AND indexname = $2
                    """
                    existing = await conn.fetchval(check_sql, index['table'], index['name'])
                    
                    if existing:
                        results['existing_indexes'].append(index['name'])
                        logger.info(f"Index {index['name']} already exists")
                        continue
                    
                    # Create the index
                    create_sql = f"""
                        CREATE INDEX CONCURRENTLY IF NOT EXISTS {index['name']} 
                        ON {index['table']} {index['columns']}
                    """
                    
                    logger.info(f"Creating index: {index['name']} - {index['description']}")
                    await conn.execute(create_sql)
                    results['created_indexes'].append(index['name'])
                    logger.info(f"Successfully created index: {index['name']}")
                    
                except Exception as e:
                    error_msg = f"Failed to create index {index['name']}: {str(e)}"
                    logger.error(error_msg)
                    results['failed_indexes'].append({
                        'name': index['name'],
                        'error': str(e)
                    })
        
        return results
    
    async def analyze_query_performance(self) -> Dict[str, Any]:
        """Analyze current query performance and suggest optimizations."""
        performance_stats = {
            'table_sizes': {},
            'index_usage': {},
            'slow_queries': []
        }
        
        async with self.db_manager.get_read_connection() as conn:
            try:
                # Get table sizes
                table_size_sql = """
                    SELECT 
                        schemaname,
                        tablename,
                        attname,
                        n_distinct,
                        correlation
                    FROM pg_stats 
                    WHERE tablename IN ('ohlcv_data', 'symbols')
                    ORDER BY tablename, attname
                """
                table_stats = await conn.fetch(table_size_sql)
                performance_stats['table_stats'] = [dict(row) for row in table_stats]
                
                # Get index usage statistics
                index_usage_sql = """
                    SELECT 
                        schemaname,
                        tablename,
                        indexname,
                        idx_tup_read,
                        idx_tup_fetch
                    FROM pg_stat_user_indexes 
                    WHERE tablename IN ('ohlcv_data', 'symbols')
                    ORDER BY idx_tup_read DESC
                """
                index_stats = await conn.fetch(index_usage_sql)
                performance_stats['index_usage'] = [dict(row) for row in index_stats]
                
                # Get table row counts
                for table in ['ohlcv_data', 'symbols']:
                    count_sql = f"SELECT COUNT(*) FROM {table}"
                    count = await conn.fetchval(count_sql)
                    performance_stats['table_sizes'][table] = count
                    
            except Exception as e:
                logger.error(f"Failed to analyze query performance: {e}")
                performance_stats['error'] = str(e)
        
        return performance_stats
    
    async def optimize_database_settings(self) -> Dict[str, Any]:
        """Apply database-level optimizations for better performance."""
        optimizations = {
            'applied': [],
            'failed': [],
            'current_settings': {}
        }
        
        # Settings to optimize for time-series data
        settings = [
            {
                'name': 'shared_buffers',
                'recommended': '256MB',
                'description': 'Increase shared buffer cache'
            },
            {
                'name': 'effective_cache_size',
                'recommended': '1GB', 
                'description': 'Estimate of available OS cache'
            },
            {
                'name': 'random_page_cost',
                'recommended': '1.1',
                'description': 'Lower cost for SSD storage'
            },
            {
                'name': 'seq_page_cost',
                'recommended': '1.0',
                'description': 'Sequential page cost baseline'
            }
        ]
        
        async with self.db_manager.get_read_connection() as conn:
            try:
                # Get current settings
                for setting in settings:
                    current_sql = "SELECT setting FROM pg_settings WHERE name = $1"
                    current_value = await conn.fetchval(current_sql, setting['name'])
                    optimizations['current_settings'][setting['name']] = current_value
                    
                logger.info("Database settings analysis completed")
                optimizations['note'] = "Settings analysis only - manual configuration required"
                
            except Exception as e:
                logger.error(f"Failed to analyze database settings: {e}")
                optimizations['error'] = str(e)
        
        return optimizations

async def run_database_optimization():
    """Main function to run database optimization tasks."""
    logger.info("Starting database optimization...")
    
    optimizer = DatabaseOptimizer()
    
    try:
        # Create performance indexes
        logger.info("Creating performance indexes...")
        index_results = await optimizer.create_performance_indexes()
        
        # Analyze performance
        logger.info("Analyzing query performance...")
        perf_results = await optimizer.analyze_query_performance()
        
        # Check database settings
        logger.info("Analyzing database settings...")
        settings_results = await optimizer.optimize_database_settings()
        
        # Summary
        logger.info("Database optimization completed!")
        logger.info(f"Created indexes: {len(index_results['created_indexes'])}")
        logger.info(f"Existing indexes: {len(index_results['existing_indexes'])}")
        logger.info(f"Failed indexes: {len(index_results['failed_indexes'])}")
        
        if index_results['failed_indexes']:
            logger.warning(f"Failed to create some indexes: {index_results['failed_indexes']}")
        
        return {
            'indexes': index_results,
            'performance': perf_results,
            'settings': settings_results
        }
        
    except Exception as e:
        logger.error(f"Database optimization failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(run_database_optimization())
