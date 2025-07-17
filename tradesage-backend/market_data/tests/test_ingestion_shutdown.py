import asyncio

import pytest


import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.services.data_ingestion import ProductionDataIngestionService
class _Dummy:
    """Minimal stub that returns no-op coroutines / attributes for any access."""

    async def __call__(self, *args, **kwargs):  # noqa: D401
        return None

    def __getattr__(self, item):
        async def _coro(*args, **kwargs):  # noqa: D401
            return None
        return _coro


@pytest.mark.asyncio
async def test_thread_pool_shutdown(capsys):
    """Ensure ThreadPoolExecutor is shut down by `close()` helper."""
    ingestion = ProductionDataIngestionService(databento_client=_Dummy(), db_manager=_Dummy(), redis_service=_Dummy())

    # Start bg tasks to mimic real life (they are immediately idle due to dummy impl).
    await ingestion.start_background_processing()

    await ingestion.close()

    assert ingestion.thread_pool._shutdown is True

    captured = capsys.readouterr()
    assert not captured.out
    assert not captured.err
