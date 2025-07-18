import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient

import os
# Ensure the app boots in *testing* mode with heavy background jobs disabled
os.environ["ENVIRONMENT"] = "development"
# Disable heavy startup processes for faster tests
os.environ.setdefault("ENABLE_CONTINUOUS_INGESTION", "false")
os.environ.setdefault("ENABLE_STARTUP_INGESTION", "false")

# ------------------------------------------------------------------
# Ensure project root is in PYTHONPATH so that 'market_data' resolves
# ------------------------------------------------------------------
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from market_data.app.main import app  # type: ignore


@pytest.mark.asyncio
async def test_full_market_data_flow():
    """End-to-end integration test for the *market_data* service.

    The test performs the following steps:

    1. Calls the global health endpoint to ensure the service is up.
    2. Retrieves the list of available symbols via ``/api/v1/ohlcv/symbols``.
    3. For **each** symbol it:
       a. Fetches standard OHLCV bars (4-day window).
       b. Fetches the *latest* OHLCV bars (4-day window).
       c. Fetches statistical *summary* (4-day window).
       d. Fetches extended symbol *info*.
       e. Retrieves filtered **trades** data (1-day window).
       f. Retrieves **latest trades** snapshot.
       g. Runs **basic trade analytics**.
       h. Retrieves **order-flow** aggregation.
    4. Calls the market summary endpoint for the first 10 symbols.
    5. Calls the ingestion **status** endpoint to verify orchestrator state.
    6. Retrieves **performance statistics** for OHLCV & trade endpoints.
    7. Exercises **TradingView-compatible** endpoints (config, symbol search, history).
    8. Calls the simple ``/api/v1/ohlcv/test`` sanity endpoint.

    The goal is to verify that the entire request/response flow — from API
    routing, through data-access layers, to external integrations (DB, Redis,
    Databento) — works without raising errors.
    """

    async with AsyncClient(app=app, base_url="http://testserver") as client:
        # ------------------------------------------------------------------
        # 1. Global health check
        # ------------------------------------------------------------------
        health_resp = await client.get("/health")
        assert health_resp.status_code == 200, health_resp.text
        assert health_resp.json().get("status") == "healthy"

        # ------------------------------------------------------------------
        # 2. Discover all symbols
        # ------------------------------------------------------------------
        symbols_resp = await client.get("/api/v1/ohlcv/symbols", params={"active_only": True})
        assert symbols_resp.status_code == 200, symbols_resp.text
        symbols_data = symbols_resp.json()["data"]["symbols"]
        assert symbols_data, "No symbols returned from symbols endpoint"

        # Time range for the last 4 days
        end_dt = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=4)

        # Concurrency limiter – avoid exhausting DB/Redis connections
        semaphore = asyncio.Semaphore(10)

        async def _test_symbol(symbol: str):
            """Run all per-symbol endpoint checks for *symbol*."""
            async with semaphore:
                # a. Standard OHLCV bars
                ohlcv_params = {
                    "timeframe": "ohlcv-1d",
                    "start_date": start_dt.isoformat(),
                    "end_date": end_dt.isoformat(),
                }
                resp = await client.get(f"/api/v1/ohlcv/{symbol}", params=ohlcv_params)
                assert resp.status_code == 200, f"OHLCV failed for {symbol}: {resp.text}"

                # b. Latest convenience endpoint (last 4 days)
                latest_params = {
                    "timeframe": "ohlcv-1d",
                    "days": 4,
                }
                resp = await client.get(f"/api/v1/ohlcv/{symbol}/latest", params=latest_params)
                assert resp.status_code == 200, f"Latest failed for {symbol}: {resp.text}"

                # c. Summary stats endpoint
                summary_params = {
                    "timeframe": "ohlcv-1d",
                    "days": 4,
                }
                resp = await client.get(f"/api/v1/ohlcv/{symbol}/summary", params=summary_params)
                assert resp.status_code == 200, f"Summary failed for {symbol}: {resp.text}"

                # d. Symbol info endpoint
                resp = await client.get(f"/api/v1/ohlcv/symbols/{symbol}/info")
                assert resp.status_code == 200, f"Symbol info failed for {symbol}: {resp.text}"

                # e. Trade data (1-day range to satisfy analytics constraints)
                trade_start = end_dt - timedelta(days=1)
                trade_params = {
                    "start_date": trade_start.isoformat(),
                    "end_date": end_dt.isoformat(),
                    "limit": 100,
                }
                trades_resp = await client.get(f"/api/v1/trades/{symbol}", params=trade_params)
                # Accept either 200 (data found) or 404 (no data yet) – but never 5xx
                assert trades_resp.status_code in (200, 404), f"Trades failed for {symbol}: {trades_resp.text}"

                # f. Latest trades endpoint
                latest_trades_resp = await client.get(f"/api/v1/trades/{symbol}/latest", params={"count": 50})
                assert latest_trades_resp.status_code in (200, 404), f"Latest trades failed for {symbol}: {latest_trades_resp.text}"

                # g. Trade analytics (basic)
                analytics_params = {
                    "start_date": trade_start.isoformat(),
                    "end_date": end_dt.isoformat(),
                    "analysis_type": "basic",
                }
                analytics_resp = await client.get(f"/api/v1/trades/{symbol}/analytics", params=analytics_params)
                assert analytics_resp.status_code in (200, 404), f"Analytics failed for {symbol}: {analytics_resp.text}"

                # h. Order-flow aggregation
                flow_params = {"timeframe": "1m", "periods": 10}
                flow_resp = await client.get(f"/api/v1/trades/{symbol}/flow", params=flow_params)
                assert flow_resp.status_code in (200, 404), f"Order flow failed for {symbol}: {flow_resp.text}"

        # ------------------------------------------------------------------
        # 3. Fire off concurrent per-symbol checks
        # ------------------------------------------------------------------
        await asyncio.gather(*(_test_symbol(sym["symbol"]) for sym in symbols_data))

        # ------------------------------------------------------------------
        # 4. Market summary for a subset (first 10 symbols)
        # ------------------------------------------------------------------
        top_symbols = ",".join(sym["symbol"] for sym in symbols_data[:10])
        summary_resp = await client.get(
            "/api/v1/ohlcv/market/summary",
            params={"symbols": top_symbols, "timeframe": "ohlcv-1d"},
        )
        assert summary_resp.status_code == 200, summary_resp.text

        # ------------------------------------------------------------------
        # 5. Ingestion status endpoint
        # ------------------------------------------------------------------
        ingest_resp = await client.get("/api/v1/ingestion/status")
        assert ingest_resp.status_code == 200, ingest_resp.text

        # ------------------------------------------------------------------
        # 6. Performance statistics endpoints
        # ------------------------------------------------------------------
        ohlcv_perf_resp = await client.get("/api/v1/ohlcv/performance/stats")
        assert ohlcv_perf_resp.status_code == 200, ohlcv_perf_resp.text

        trades_perf_resp = await client.get("/api/v1/trades/performance/stats")
        assert trades_perf_resp.status_code == 200, trades_perf_resp.text

        # ------------------------------------------------------------------
        # 7. TradingView compatibility endpoints
        # ------------------------------------------------------------------
        tv_config_resp = await client.get("/api/v1/tradingview/config")
        assert tv_config_resp.status_code == 200, tv_config_resp.text

        first_symbol = symbols_data[0]["symbol"]
        tv_history_params = {
            "resolution": "1D",
            "from_timestamp": int(start_dt.timestamp()),
            "to_timestamp": int(end_dt.timestamp()),
            "countback": 30,
        }
        tv_history_resp = await client.get(f"/api/v1/tradingview/{first_symbol}/history", params=tv_history_params)
        assert tv_history_resp.status_code == 200, tv_history_resp.text
        # The TradingView API returns 's' = 'ok' or 'no_data' for success cases
        assert tv_history_resp.json().get("s") != "error"

        tv_search_resp = await client.get("/api/v1/tradingview/symbols", params={"symbol": first_symbol[:3]})
        assert tv_search_resp.status_code == 200, tv_search_resp.text

        # ------------------------------------------------------------------
        # 5. Basic router self-test endpoint
        # ------------------------------------------------------------------
        test_resp = await client.get("/api/v1/ohlcv/test")
        assert test_resp.status_code == 200, test_resp.text
        assert test_resp.json()["data"]["status"] == "working"
