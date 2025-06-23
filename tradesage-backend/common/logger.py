import logging
import sys
import datetime
import json

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

class SecurityLogger:
    """Enhanced logger for security events."""
    
    @staticmethod
    def log_auth_event(event_type: str, user_id: str, status: str, metadata: dict = None):
        """Log authentication events with structured data."""
        log_data = {
            "event": event_type,
            "user_id": user_id,
            "status": status,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
        if metadata:
            log_data.update(metadata)
            
        logger.info(json.dumps(log_data), extra={"log_type": "security"})

    @staticmethod
    def log_transaction_rollback(operation: str, error: Exception):
        """Log database transaction failures."""
        logger.error(
            f"Transaction rollback for {operation}: {str(error)}",
            exc_info=True,
            extra={"log_type": "transaction"}
        )