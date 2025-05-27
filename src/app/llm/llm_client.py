# src/app/llm/llm_client.py
import os
import logging
from dotenv import load_dotenv

# Import the provider classes and base class
from .providers import LLMProvider, OpenAIProvider, GoogleGeminiProvider # Added GoogleGeminiProvider

logger = logging.getLogger(__name__)
load_dotenv()

_llm_client_instance: Optional[LLMProvider] = None # Added type hint

def get_llm_client() -> LLMProvider:
    """
    Factory function to get an instance of the configured LLM provider.
    Reads LLM_PROVIDER from environment variables.
    Caches the client instance.
    """
    global _llm_client_instance

    if _llm_client_instance is not None:
        # Optional: Add a check if LLM_PROVIDER has changed since caching
        # For simplicity, current behavior reuses instance until app restart if provider changes in .env
        logger.debug("Returning cached LLM client instance.")
        return _llm_client_instance

    provider_name = os.getenv("LLM_PROVIDER", "openai").lower() # Default to openai
    logger.info(f"Attempting to initialize LLM client for provider: {provider_name}")

    try:
        if provider_name == "openai":
            _llm_client_instance = OpenAIProvider()
            logger.info("Successfully initialized OpenAI client.")
        elif provider_name == "google": # New case for Google Gemini
            _llm_client_instance = GoogleGeminiProvider()
            logger.info("Successfully initialized Google Gemini client.")
        # --- Add other providers later ---
        # elif provider_name == "anthropic":
        #     _llm_client_instance = AnthropicProvider()
        else:
            logger.error(f"Unsupported LLM_PROVIDER specified: {provider_name}")
            raise ValueError(f"Unsupported LLM_PROVIDER: {provider_name}")
    except ValueError as ve: # Catch known errors from provider init (e.g., missing API key)
        logger.error(f"Configuration error initializing LLM provider '{provider_name}': {ve}", exc_info=True)
        raise # Re-raise to prevent app from starting with misconfigured LLM
    except Exception as e: # Catch any other unexpected errors during init
        logger.error(f"Unexpected error initializing LLM provider '{provider_name}': {e}", exc_info=True)
        raise ValueError(f"Failed to initialize LLM provider '{provider_name}': {e}") from e

    return _llm_client_instance