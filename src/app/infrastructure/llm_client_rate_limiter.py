# src/app/infrastructure/llm_client_rate_limiter.py
import logging
from typing import Dict, Optional

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
    
    provider_rate_limiters['openai'] = AsyncRateLimiter(
        settings.OPENAI_REQUESTS_PER_MINUTE,
        settings.OPENAI_TOKENS_PER_MINUTE
    )
    logger.info(f"OpenAI rate limit set to {settings.OPENAI_REQUESTS_PER_MINUTE} RPM and {settings.OPENAI_TOKENS_PER_MINUTE} TPM.")
    
    provider_rate_limiters['google'] = AsyncRateLimiter(
        settings.GOOGLE_REQUESTS_PER_MINUTE,
        settings.GOOGLE_TOKENS_PER_MINUTE
    )
    logger.info(f"Google rate limit set to {settings.GOOGLE_REQUESTS_PER_MINUTE} RPM and {settings.GOOGLE_TOKENS_PER_MINUTE} TPM.")

    provider_rate_limiters['anthropic'] = AsyncRateLimiter(
        settings.ANTHROPIC_REQUESTS_PER_MINUTE,
        settings.ANTHROPIC_TOKENS_PER_MINUTE
    )
    logger.info(f"Anthropic rate limit set to {settings.ANTHROPIC_REQUESTS_PER_MINUTE} RPM and {settings.ANTHROPIC_TOKENS_PER_MINUTE} TPM.")
    
    logger.info("Global LLM rate limiters initialization complete.")

def get_rate_limiter_for_provider(provider_name: str) -> Optional[AsyncRateLimiter]:
    """
    Retrieves the rate limiter for a specific provider.
    Provider names are matched case-insensitively.
    """
    return provider_rate_limiters.get(provider_name.lower())