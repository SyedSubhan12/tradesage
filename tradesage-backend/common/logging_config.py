import logging
import sys
import structlog
from .config import settings

def setup_logging():
    """
    Set up structured logging for the application.
    In development, logs are human-readable.
    In production, logs are JSON-formatted.
    """
    shared_processors = [
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if settings.environment == "production":
        processors = shared_processors + [
            structlog.processors.JSONRenderer(),
        ]
    else:
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(),
        ]

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure root logger to pass everything to structlog
    root_logger = logging.getLogger()
    handler = logging.StreamHandler(sys.stdout)
    # The formatter is handled by structlog
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO if settings.environment == "production" else logging.DEBUG)

    # Silence other noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    logger = structlog.get_logger("tradesage.logging")
    logger.info("Structured logging configured.", environment=settings.environment)