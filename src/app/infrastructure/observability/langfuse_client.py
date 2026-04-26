"""Langfuse v3 SDK singleton + LangChain callback factory.

Constructs a single `Langfuse` client on first use; subsequent calls
return the same instance. Disabled when `LANGFUSE_ENABLED=False` or when
a secret key is missing — both `get_langfuse()` and
`get_langchain_handler()` return `None` so call sites short-circuit
without branching on settings.

Fail-open: any exception during construction or flush is caught and
logged at WARNING; the client transitions to a permanently-disabled
state for the process lifetime so we don't burn retry cost on a broken
config. The SDK itself runs with a short `flush_interval` so it never
blocks the worker on a network hiccup; the outer try/except around span
open / update / exit in `LLMClient` is the actual fail-open guarantee.

Trace IDs are bound to `correlation_id_var.get()` at handler-creation
time, so each `get_langchain_handler()` call returns a fresh handler
scoped to the current request / scan. The same correlation ID flows
through the SCCAP middleware (`main.py`) and the worker consumer
(`consumer.py`) so logs in Loki cross-reference Langfuse traces by
`X-Correlation-ID`.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Optional

from app.config.config import settings
from app.config.logging_config import correlation_id_var
from app.infrastructure.observability.mask import mask

logger = logging.getLogger(__name__)

# Module-level state. `_init_lock` guards the lazy first-time
# construction; `_disabled` latches True on any unrecoverable error so
# we don't keep retrying.
_lock = threading.Lock()
_client: Optional[Any] = None
_disabled: bool = False


def _is_configured() -> bool:
    if not settings.LANGFUSE_ENABLED:
        return False
    secret = settings.LANGFUSE_SECRET_KEY
    public = settings.LANGFUSE_PUBLIC_KEY
    if secret is None or public is None:
        return False
    secret_val = (
        secret.get_secret_value()
        if secret is not None and hasattr(secret, "get_secret_value")
        else str(secret) if secret is not None else ""
    )
    public_val = (
        public.get_secret_value()
        if public is not None and hasattr(public, "get_secret_value")
        else str(public) if public is not None else ""
    )
    return bool(secret_val) and bool(public_val)


def get_langfuse() -> Optional[Any]:
    """Return the singleton Langfuse client, or None if disabled / failed."""
    global _client, _disabled

    if _disabled:
        return None
    if _client is not None:
        return _client
    if not _is_configured():
        return None

    with _lock:
        if _disabled:
            return None
        if _client is not None:
            return _client
        try:
            from langfuse import Langfuse  # type: ignore[import-not-found]

            secret = settings.LANGFUSE_SECRET_KEY
            public = settings.LANGFUSE_PUBLIC_KEY
            secret_val = (
                secret.get_secret_value()
                if secret is not None and hasattr(secret, "get_secret_value")
                else str(secret) if secret is not None else ""
            )
            public_val = (
                public.get_secret_value()
                if public is not None and hasattr(public, "get_secret_value")
                else str(public) if public is not None else ""
            )

            _client = Langfuse(
                public_key=public_val,
                secret_key=secret_val,
                host=settings.LANGFUSE_HOST,
                # Fail-open: never block the worker on a Langfuse fault.
                flush_interval=5,
                # Drop events rather than retrying on the request path.
                # SDK still flushes its in-process buffer asynchronously.
                tracing_enabled=True,
                mask=mask,
            )
            logger.info(
                "Langfuse SDK initialised", extra={"host": settings.LANGFUSE_HOST}
            )
        except Exception as e:
            _disabled = True
            _client = None
            logger.warning(
                "Langfuse SDK initialisation failed; disabling for this process. "
                "Error: %s",
                e,
                exc_info=True,
            )
            return None

    return _client


def get_langchain_handler() -> Optional[Any]:
    """Return a LangChain CallbackHandler bound to the current correlation_id.

    Each invocation builds a fresh handler so its `trace_id` matches the
    correlation_id at the time of the call (the ContextVar may differ
    per request / per scan).
    """
    if get_langfuse() is None:
        return None
    try:
        from langfuse.langchain import CallbackHandler  # type: ignore[import-not-found]

        corr_id = correlation_id_var.get()
        handler = CallbackHandler()
        # Stamp the trace + session ids from our correlation context so
        # logs in Loki and traces in Langfuse cross-reference cleanly.
        # The handler exposes these via attributes the SDK reads at
        # span-emit time.
        try:
            handler.trace_id = corr_id  # type: ignore[attr-defined]
            handler.session_id = corr_id  # type: ignore[attr-defined]
        except Exception:
            # Older / newer SDKs may not expose these fields; the
            # observe-decorator path still produces a usable trace.
            pass
        return handler
    except Exception as e:
        logger.warning(
            "Failed to build Langfuse LangChain CallbackHandler: %s", e, exc_info=True
        )
        return None


def flush_langfuse() -> None:
    """Best-effort flush. Called from FastAPI lifespan shutdown."""
    if _client is None:
        return
    try:
        _client.flush()
    except Exception as e:
        logger.warning("Langfuse flush failed: %s", e)


def reset_for_tests() -> None:
    """Test-only: drop the singleton so tests can re-enter init paths."""
    global _client, _disabled
    with _lock:
        _client = None
        _disabled = False
