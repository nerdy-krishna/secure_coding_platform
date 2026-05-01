# src/app/infrastructure/llm_client_rate_limiter.py
import logging
from typing import Dict

from app.config.config import settings
from app.shared.lib.rate_limiter import AsyncRateLimiter

logger = logging.getLogger(__name__)

# A global registry for provider-specific rate limiters.
# This ensures that all parts of the application share the same limiters.
provider_rate_limiters: Dict[str, AsyncRateLimiter] = {}


def initialize_rate_limiters():
    """
    Initializes the rate limiters based on the application settings.
    This should be called once on application startup.
    """
    global provider_rate_limiters
    if provider_rate_limiters:
        logger.info("Rate limiters are already initialized.")
        return

    logger.info("Initializing global LLM provider rate limiters...")

    _limiters: Dict[str, AsyncRateLimiter] = {}

    try:
        _limiters["openai"] = AsyncRateLimiter(
            settings.OPENAI_REQUESTS_PER_MINUTE, settings.OPENAI_TOKENS_PER_MINUTE
        )
    except Exception as e:
        logger.error(
            "rate_limiter.init_failed",
            extra={"provider": "openai", "error_class": e.__class__.__name__},
            exc_info=True,
        )
        raise
    logger.info(
        "rate_limiter.configured",
        extra={
            "provider": "openai",
            "rpm": settings.OPENAI_REQUESTS_PER_MINUTE,
            "tpm": settings.OPENAI_TOKENS_PER_MINUTE,
        },
    )

    try:
        _limiters["google"] = AsyncRateLimiter(
            settings.GOOGLE_REQUESTS_PER_MINUTE, settings.GOOGLE_TOKENS_PER_MINUTE
        )
    except Exception as e:
        logger.error(
            "rate_limiter.init_failed",
            extra={"provider": "google", "error_class": e.__class__.__name__},
            exc_info=True,
        )
        raise
    logger.info(
        "rate_limiter.configured",
        extra={
            "provider": "google",
            "rpm": settings.GOOGLE_REQUESTS_PER_MINUTE,
            "tpm": settings.GOOGLE_TOKENS_PER_MINUTE,
        },
    )

    try:
        _limiters["anthropic"] = AsyncRateLimiter(
            settings.ANTHROPIC_REQUESTS_PER_MINUTE, settings.ANTHROPIC_TOKENS_PER_MINUTE
        )
    except Exception as e:
        logger.error(
            "rate_limiter.init_failed",
            extra={"provider": "anthropic", "error_class": e.__class__.__name__},
            exc_info=True,
        )
        raise
    logger.info(
        "rate_limiter.configured",
        extra={
            "provider": "anthropic",
            "rpm": settings.ANTHROPIC_REQUESTS_PER_MINUTE,
            "tpm": settings.ANTHROPIC_TOKENS_PER_MINUTE,
        },
    )

    # Atomic publish: assign the completed dict all at once so concurrent
    # readers never see a half-populated registry (V15.4.1).
    provider_rate_limiters.update(_limiters)

    logger.info("Global LLM rate limiters initialization complete.")


def get_rate_limiter_for_provider(provider_name: str) -> AsyncRateLimiter:
    """
    Retrieves the rate limiter for a specific provider.
    Provider names are matched case-insensitively.
    Raises RuntimeError if rate limiters have not been initialized yet.
    """
    if not provider_rate_limiters:
        raise RuntimeError(
            "LLM rate limiters not initialized — call initialize_rate_limiters() at startup"
        )
    limiter = provider_rate_limiters.get(provider_name.lower())
    if limiter is None:
        raise RuntimeError(f"No rate limiter configured for provider '{provider_name}'")
    return limiter
