import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app.utils.config import get_settings


def test_settings_defaults():
    """Ensure newly added schedule-related settings are present with expected defaults."""
    settings = get_settings()

    assert settings.HISTORICAL_START_DATE == "2010-01-01"
    assert settings.INCREMENTAL_UPDATE_CRON == "0 */1 * * *"
    assert settings.SYMBOL_REFRESH_CRON == "0 6 * * *"
    assert settings.MAINTENANCE_CRON == "0 2 * * 0"
    assert settings.MAX_CONCURRENT_DATASETS == 3
    assert settings.PAUSE_BETWEEN_DATASETS_SECONDS == 30
