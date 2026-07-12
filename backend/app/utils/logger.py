"""
Legacy logger utility — delegates to the observability logging system.

This module exists for backward compatibility with any code that imports
from app.utils.logger. The structured logging is configured via
app.observability.logging_config.setup_logging().
"""
import logging

logger = logging.getLogger("ai_security_auditor")
