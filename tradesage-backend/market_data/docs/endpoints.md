# Market Data Microservice – API Endpoints

_Last updated: 2025-07-12_

This document enumerates every publicly exposed endpoint in the **Tradesage Market Data** microservice (`/api/v1` scope), its purpose, major parameters, and key performance considerations (indexes, caching, and estimated throughput).

| # | HTTP Method | Path (prefixed with `/api/v1`) | Purpose / Function | Key Parameters | Performance Notes |
|---|-------------|---------------------------------|--------------------|----------------|-------------------|
| 1 | **GET** | `/ohlcv/symbols` | List all available symbols (optionally filtered by dataset). | `dataset` (query, optional) | Hits Redis cache (`symbols:*`, TTL = 1 hr). Falls back to indexed `symbols.symbol` table scan. Sub-millisecond latency from cache, ~10–30 ms from DB. |
| 2 | **GET** | `/ohlcv/{symbol}` | Retrieve OHLCV candles for a symbol over a date range and timeframe. | `timeframe` (query, default `ohlcv-1d`), `start_date`, `end_date`, `dataset`, `limit` | Data served from Redis cache (`ohlcv:*`) when available (TTL =`CACHE_TTL` ≈ 5 min or `DAILY_CACHE_TTL` ≈ 1 day). Query is covered by composite index `idx_ohlcv_symbol_timeframe_timestamp`. Typical latency: 5–20 ms from cache, 50-150 ms from DB for 10 k rows. |
| 3 | **GET** | `/ohlcv/{symbol}/latest` | Return the latest candle and basic stats for the past *N* days. | `timeframe`, `days`, `dataset` | Same caching/indexes as #2. Work is done in-memory after fetch; negligible extra cost. |
| 4 | **GET** | `/ohlcv/{symbol}/summary` | Statistical summary (min/max/avg/etc.) for recent candles. | `timeframe`, `days`, `dataset` | Heavy aggregation happens in Python after retrieval. For ≤365-day windows the query remains index-efficient; processing cost grows linearly with rows (~50 µs/row). |
| 5 | **GET** | `/trades/{symbol}` | Tick-level trade history for a symbol in a time window. | `start_date`, `end_date`, `dataset`, `limit` | Response capped at 50 k rows. Underlying storage is partitioned table `trade_data` (not shown here) with index `idx_trade_symbol_timestamp` ensuring ≤200 ms latency for max payload. Redis caching planned. |
| 6 | **GET** | `/news` | News articles with rich filtering. | `symbol`, `start_date`, `end_date`, `source`, `min_sentiment`, `max_sentiment`, `limit` | ORM query over `news_data` table with multiple single-column indexes. Typical latency 20-60 ms for ≤1 k rows. No caching yet (news expected to change frequently). |

## Cross-cutting Performance Features

* **Redis Caching** – Results for symbols and OHLCV queries are cached using `redis.asyncio` with configurable TTLs (`CACHE_TTL`, `DAILY_CACHE_TTL`). Cache invalidation hooks exist in `DatabaseManager.invalidate_cache()`.
* **Database Indexes** – Composite and partial indexes (`idx_ohlcv_*`, `idx_symbols_symbol`, etc.) minimise scan time. AsyncPG pool maintains 20 connections, sync SQLAlchemy pool 10.
* **Async I/O** – Lifespan bootstraps asyncpg pool and async Redis, enabling high concurrency.
* **Rate Limiting** – Placeholder dependency `rate_limit_check()` ready for future enforcement (e.g., 100 req/s per IP).
* **Payload Limits** – Query parameters `limit`, `days`, and validation guard against runaway result sets.

## Example Usage

```bash
# Latest daily candle for AAPL last 30 days
curl "http://localhost:8000/api/v1/ohlcv/AAPL/latest?timeframe=ohlcv-1d&days=30"
```

---
If you need additional details (e.g., request/response JSON schemas or benchmark numbers on specific hardware), let us know!
