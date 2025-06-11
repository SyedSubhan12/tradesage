import logging

audit_logger = logging.getLogger("tradesage.audit")


async def log_audit_event(event_type: str, user_id: str = None, details: dict = None):
    """Logs an audit event asynchronously"""
    log_data = {
        "event_type": event_type,
        "user_id": user_id,
        "details": details if details is not None else {}
    }
    # Use async logging if needed, or just call sync logger
    audit_logger.info("Audit Event", extra=log_data)