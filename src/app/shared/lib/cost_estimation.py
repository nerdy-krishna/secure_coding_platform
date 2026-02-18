# src/app/shared/lib/cost_estimation.py

import logging
from typing import Dict, Optional

import tiktoken
import anthropic
import google.genai as genai

# Import the database model to use for type hinting
from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)



# Cache for Google GenAI clients to reuse connections/sessions
_google_client_cache: Dict[str, genai.Client] = {}

def _get_cached_google_client(api_key: str) -> genai.Client:
    if api_key not in _google_client_cache:
        _google_client_cache[api_key] = genai.Client(api_key=api_key)
    return _google_client_cache[api_key]


async def count_tokens(
    text: str, 
    config: db_models.LLMConfiguration, 
    api_key: Optional[str] = None
) -> int:
    """
    Counts tokens using the provider-specific method for accuracy.
    - OpenAI: Uses the specified tiktoken encoding.
    - Anthropic: Uses the official offline tokenizer.
    - Google: Uses an API call for the most accurate count.
    """
    if not text:
        return 0

    provider = config.provider.lower()

    try:
        if provider == "openai":
            # Try to get encoding for the specific model first, fallback to config or default
            try:
                encoding = tiktoken.encoding_for_model(config.model_name)
            except KeyError:
                # Model not found, use a hardcoded default encoding for OpenAI.
                logger.warning(f"Could not find a tiktoken tokenizer for '{config.model_name}'. Falling back to 'cl100k_base'.")
                encoding = tiktoken.get_encoding("cl100k_base")
            return len(encoding.encode(text, disallowed_special=()))

        elif provider == "anthropic":
            if not api_key:
                logger.warning("Anthropic API key not provided for token counting. Falling back to tiktoken estimate.")
                # Use tiktoken as fallback for Anthropic (they use similar tokenization)
                encoding = tiktoken.get_encoding("cl100k_base")
                return len(encoding.encode(text, disallowed_special=()))
            
            # Use Anthropic's client to count tokens
            client = anthropic.Anthropic(api_key=api_key)
            response = client.messages.count_tokens(
                model=config.model_name,
                messages=[{"role": "user", "content": text}]
            )
            return response.input_tokens

        elif provider == "google":
            # Try to get key from config if not provided explicitly
            effective_api_key = api_key
            if not effective_api_key and hasattr(config, "decrypted_api_key"):
                 effective_api_key = config.decrypted_api_key

            if not effective_api_key:
                logger.warning("Google API key not provided for token counting. Falling back to a rough estimate (len/4).")
                return len(text) // 4
            
            # Simple caching for GenAI client to avoid overhead of recreation
            client = _get_cached_google_client(effective_api_key)
            
            response = await client.aio.models.count_tokens(
                model=config.model_name,
                contents=text
            )
            if response.total_tokens is None:
                return 0
            else:
                return response.total_tokens

        else:
            logger.warning(f"Unsupported provider '{provider}' for token counting. Falling back to tiktoken.")
            encoding = tiktoken.get_encoding(config.tokenizer_encoding or "cl100k_base")
            return len(encoding.encode(text, disallowed_special=()))
            
    except Exception as e:
        logger.error(f"Failed to count tokens for provider {provider} with model {config.model_name}: {e}. Falling back to len/4 estimate.", exc_info=True)
        return len(text) // 4


def estimate_cost_for_prompt(
    config: db_models.LLMConfiguration,
    input_tokens: int,
    output_token_percentage: float = 0.25,
) -> Dict[str, float]:
    """
    Estimates the cost for a prompt BEFORE the API call.
    - Calculates exact input cost.
    - Predicts output tokens based on a percentage of input tokens.
    - Returns a dictionary with the cost breakdown.
    """
    # 1. Calculate exact input cost
    input_cost = (input_tokens / 1_000_000) * float(config.input_cost_per_million)

    # 2. Predict output tokens and calculate their estimated cost
    predicted_output_tokens = int(input_tokens * output_token_percentage)
    predicted_output_cost = (
        predicted_output_tokens / 1_000_000
    ) * float(config.output_cost_per_million)

    total_estimated_cost = input_cost + predicted_output_cost
    
    logger.debug(
        f"Cost Estimation for {config.model_name}: "
        f"Input Tokens={input_tokens}, Predicted Output Tokens={predicted_output_tokens}"
    )

    return {
        "input_cost": input_cost,
        "predicted_output_cost": predicted_output_cost,
        "total_estimated_cost": total_estimated_cost,
        "predicted_output_tokens": float(predicted_output_tokens),
        "total_input_tokens": float(input_tokens),
    }


def calculate_actual_cost(
    config: db_models.LLMConfiguration,
    prompt_tokens: int,
    completion_tokens: int,
) -> float:
    """
    Calculates the exact cost of an LLM API call AFTER it has completed,
    using the precise token counts from the API response.
    """
    input_cost = (prompt_tokens / 1_000_000) * float(config.input_cost_per_million)
    output_cost = (completion_tokens / 1_000_000) * float(config.output_cost_per_million)
    total_cost = input_cost + output_cost

    logger.info(
        f"Actual cost for {config.model_name} ({prompt_tokens} in, "
        f"{completion_tokens} out): ${total_cost:.6f}"
    )
    return total_cost
