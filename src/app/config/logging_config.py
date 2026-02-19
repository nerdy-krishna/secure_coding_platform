# src/app/config/logging_config.py

import logging
import json
import os
from contextvars import ContextVar
from typing import Any

# Context variable to hold the correlation ID for each request/task
correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="N/A")


class JSONFormatter(logging.Formatter):
    """
    Custom logging formatter to output logs in a structured JSON format.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Create a dictionary with standard log attributes
        log_object: dict[str, Any] = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage(),
            "logger_name": record.name,
            "func_name": record.funcName,
            "correlation_id": correlation_id_var.get(),
            "service_name": os.getenv("SERVICE_NAME", "unknown"),
        }

        # Add exception info if it exists
        if record.exc_info:
            log_object["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(log_object)


# The main logging configuration dictionary
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": JSONFormatter,
        },
    },
    "handlers": {
        "default": {
            "class": "logging.StreamHandler",
            "formatter": "json",
            "stream": "ext://sys.stdout",
        },
        "file": {
            "class": "logging.FileHandler",
            "formatter": "json",
            "filename": "app_debug.log",
            "mode": "a",
        },
    },
    "loggers": {
        "app": {"handlers": ["default", "file"], "level": "DEBUG", "propagate": False},
        "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
        "uvicorn.error": {"handlers": ["default"], "level": "INFO", "propagate": False},
        "uvicorn.access": {
            "handlers": ["default"],
            "level": "INFO",
            "propagate": False,
        },
        "sqlalchemy": {"handlers": ["default"], "level": "WARNING", "propagate": False},
        "pika": {"handlers": ["default"], "level": "WARNING", "propagate": False},
        "py.warnings": {
            "handlers": ["default"],
            "level": "WARNING",
            "propagate": False,
        },
        "langgraph": {"handlers": ["default"], "level": "INFO", "propagate": False},
        # Root logger
        "": {"handlers": ["default", "file"], "level": "INFO"},
    },
}


def update_logging_level(level: str):
    """
    Dynamically updates the logging level for the 'app' and root loggers.
    """
    level = level.upper()
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if level not in valid_levels:
        raise ValueError(f"Invalid log level: {level}")

    # Update the configuration dictionary (for future reference if needed)
    LOGGING_CONFIG["loggers"]["app"]["level"] = level
    LOGGING_CONFIG["loggers"][""]["level"] = level

    # Apply changes to active loggers
    logger = logging.getLogger("app")
    logger.setLevel(level)
    logging.getLogger().setLevel(level)

    # Also update specific third-party loggers if we want them to be verbose in DEBUG
    # However, for now let's keep it simple and just update the main app loggers
    # as too much noise from libraries can be overwhelming.

    logger.info(f"Log level updated to {level}")
