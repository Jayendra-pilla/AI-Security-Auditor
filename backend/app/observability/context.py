"""
Request-scoped context variables for observability.

These contextvars propagate request_id, user_id, and scan_id through
the entire call stack without requiring explicit parameter passing.
Every logger in the application automatically picks up these values
via the structured log formatter.
"""
import contextvars

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
user_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("user_id", default="-")
scan_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("scan_id", default="-")
