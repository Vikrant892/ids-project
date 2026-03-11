"""
Structured logging using structlog.
Every log entry is JSON-formatted for easy parsing and observability.
"""
import logging
import sys
from pathlib import Path
import structlog
from src.utils.config import config

def setup_logging():
    """Configure structlog for structured JSON output to file + stdout."""
    Path(config.LOG_FILE).parent.mkdir(parents=True, exist_ok=True)

    log_level = getattr(logging, config.LOG_LEVEL.upper(), logging.INFO)

    # Standard library handler — file
    file_handler = logging.FileHandler(config.LOG_FILE)
    file_handler.setLevel(log_level)

    # Standard library handler — console
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)

    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        handlers=[file_handler, console_handler]
    )

    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

def get_logger(name: str):
    setup_logging()
    return structlog.get_logger(name)
