"""
Structured JSON logging configuration with secret redaction.

Provides:
- JsonFormatter: outputs each log line as a single JSON object
- SecretRedactionFilter: strips API keys, passwords, and secrets from output
- setup_logging(): one-call configuration entry point
"""
import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional

from app.observability.context import request_id_var, user_id_var, scan_id_var


# ---------------------------------------------------------------------------
# Patterns for secret redaction
# ---------------------------------------------------------------------------

# Matches common secret-like values in log messages
_SECRET_PATTERNS = [
    re.compile(r'("?GEMINI_API_KEY"?\s*[=:]\s*["\']?)[^"\'\s,}]+(["\']?)', re.IGNORECASE),
    re.compile(r'("?JWT_SECRET_KEY"?\s*[=:]\s*["\']?)[^"\'\s,}]+(["\']?)', re.IGNORECASE),
    re.compile(r'("?password"?\s*[=:]\s*["\']?)[^"\'\s,}]+(["\']?)', re.IGNORECASE),
    re.compile(r'("?api_key"?\s*[=:]\s*["\']?)[^"\'\s,}]+(["\']?)', re.IGNORECASE),
    re.compile(r'("?secret"?\s*[=:]\s*["\']?)[^"\'\s,}]+(["\']?)', re.IGNORECASE),
    re.compile(r'("?key"?\s*[=:]\s*["\']?)[A-Za-z0-9_\-\.]{20,}(["\']?)', re.IGNORECASE),
    re.compile(r'("?Authorization"?\s*[=:]\s*["\']?Bearer\s+)[^"\'\s,}]+(["\']?)', re.IGNORECASE),
    re.compile(r'("?Cookie"?\s*[=:]\s*["\']?)[^"\'\s,}]+(["\']?)', re.IGNORECASE),
    re.compile(r'(:\/\/[^:]+:)[^@]+(@)', re.IGNORECASE),
]


def redact_secrets(message: str) -> str:
    """Replace secret-like values in a message string with ***REDACTED***."""
    result = message
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(r'\1***REDACTED***\2', result)
    return result


# ---------------------------------------------------------------------------
# Secret Redaction Filter
# ---------------------------------------------------------------------------

class SecretRedactionFilter(logging.Filter):
    """Logging filter that redacts secrets from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.msg and isinstance(record.msg, str):
            record.msg = redact_secrets(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: redact_secrets(str(v)) if isinstance(v, str) else v
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    redact_secrets(str(a)) if isinstance(a, str) else a
                    for a in record.args
                )
        return True


# ---------------------------------------------------------------------------
# JSON Formatter
# ---------------------------------------------------------------------------

class JsonFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON objects.

    Output fields:
        timestamp, level, logger, message, request_id, user_id, scan_id,
        module, funcName, lineno, exc_info (if present)
    """

    def format(self, record: logging.LogRecord) -> str:
        # Build the base message (includes string formatting of args)
        message = record.getMessage()

        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
            "request_id": request_id_var.get("-"),
            "user_id": user_id_var.get("-"),
            "scan_id": scan_id_var.get("-"),
            "module": record.module,
            "funcName": record.funcName,
            "lineno": record.lineno,
        }

        # Include exception info if present
        if record.exc_info and record.exc_info[1] is not None:
            log_entry["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


# ---------------------------------------------------------------------------
# Setup function
# ---------------------------------------------------------------------------

def setup_logging(log_level: Optional[str] = None) -> None:
    """
    Configure the root logger with structured JSON output and secret redaction.

    Args:
        log_level: Logging level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
                   Defaults to INFO if not provided.
    """
    level = getattr(logging, (log_level or "INFO").upper(), logging.INFO)

    # Create handler
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(SecretRedactionFilter())

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers to avoid duplicates
    root_logger.handlers.clear()
    root_logger.addHandler(handler)

    # Quiet noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(level)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
