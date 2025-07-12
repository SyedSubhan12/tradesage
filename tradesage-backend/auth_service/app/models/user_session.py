"""Compatibility wrapper for `UserSession` model.

Legacy code in `common.models` references `auth_service.app.models.user_session.UserSession`.
The actual implementation now lives in `common.models.user_session`.  To avoid
changing all existing relationship strings (which would require a
migration/commit across multiple services) we expose a thin wrapper module that
re-exports the model and enum.
"""

from common.models.user_session import UserSession, SessionState  # noqa: F401

__all__ = ["UserSession", "SessionState"]
