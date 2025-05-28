import os
import logging
from dotenv import load_dotenv
from typing import Optional  # Import Optional for type hinting

# Import the provider classes and base class
# Ensure LLMProvider is correctly defined/imported in providers.py for the type hint below
from .providers import LLMProvider, OpenAIProvider, GoogleGeminiProvider

logger = logging.getLogger(__name__)
load_dotenv()

# Cache the client instance to avoid re-initialization
_llm_client_instance: Optional[LLMProvider] = None  # Type hint using Optional


def get_llm_client() -> LLMProvider:
    """
    Factory function to get an instance of the configured LLM provider.
    Reads LLM_PROVIDER from environment variables.
    Caches the client instance.
    """
    global _llm_client_instance

    if _llm_client_instance is not None:
        logger.debug("Returning cached LLM client instance.")
        return _llm_client_instance

    provider_name = os.getenv("LLM_PROVIDER", "openai").lower()
    logger.info(f"Attempting to initialize LLM client for provider: {provider_name}")

    if provider_name == "openai":
        try:
            _llm_client_instance = OpenAIProvider()
            logger.info("Successfully initialized OpenAI client.")
        except Exception as e:
            logger.error(
                f"Failed to create OpenAIProvider instance: {e}", exc_info=True
            )
            raise ValueError(
                f"Failed to initialize LLM provider '{provider_name}': {e}"
            ) from e
    elif provider_name == "google":  # Assuming "google" is the env var value for Gemini
        try:
            _llm_client_instance = GoogleGeminiProvider()
            logger.info("Successfully initialized GoogleGeminiProvider client.")
        except Exception as e:
            logger.error(
                f"Failed to create GoogleGeminiProvider instance: {e}", exc_info=True
            )
            raise ValueError(
                f"Failed to initialize LLM provider '{provider_name}': {e}"
            ) from e
    # Add other providers later if needed (e.g., Anthropic)
    # elif provider_name == "anthropic":
    # _llm_client_instance = AnthropicProvider()
    else:
        logger.error(f"Unsupported LLM_PROVIDER specified: {provider_name}")
        raise ValueError(f"Unsupported LLM_PROVIDER: {provider_name}")

    return _llm_client_instance
