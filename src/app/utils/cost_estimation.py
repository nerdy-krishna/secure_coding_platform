import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)

# --- Updated Model Costs (as of mid-2025) ---
# Prices per 1 Million tokens.
MODEL_PRICING: Dict[str, Dict[str, float]] = {
    # OpenAI
    "gpt-4o": {
        "input_cost_per_million": 5.00,
        "output_cost_per_million": 15.00,
    },
    "gpt-4o-mini": {
        "input_cost_per_million": 0.15,
        "output_cost_per_million": 0.60,
    },
    "gpt-4-turbo": {
        "input_cost_per_million": 10.00,
        "output_cost_per_million": 30.00,
    },
    # Google
    "gemini-1.5-pro-latest": {
        "input_cost_per_million": 3.50,
        "output_cost_per_million": 10.50,
    },
    "gemini-2.0-flash": {
        "input_cost_per_million": 0.10,
        "output_cost_per_million": 0.40,
    },
    # Anthropic
    "claude-3-opus-20240229": {
        "input_cost_per_million": 15.00,
        "output_cost_per_million": 75.00,
    },
    "claude-3-sonnet-20240229": {
        "input_cost_per_million": 3.00,
        "output_cost_per_million": 15.00,
    },
    "claude-3-haiku-20240307": {
        "input_cost_per_million": 0.25,
        "output_cost_per_million": 1.25,
    },
}


def calculate_cost(
    model_name: Optional[str],
    input_tokens: Optional[int],
    output_tokens: Optional[int],
) -> Optional[float]:
    """
    Estimates the cost of an LLM API call based on model and token counts.
    Handles unknown models gracefully by returning None.

    Args:
        model_name: The name of the LLM model used (e.g., 'gpt-4o-mini').
        input_tokens: The number of input tokens consumed.
        output_tokens: The number of output tokens generated.

    Returns:
        The estimated cost in USD, or None if pricing info is missing.
    """
    # Ensure we have the necessary data for calculation
    if not model_name or input_tokens is None or output_tokens is None:
        return None

    # Find the pricing for the specified model
    pricing = MODEL_PRICING.get(model_name)
    if not pricing:
        logger.warning(
            f"Cost estimation not available: Pricing information not found for model '{model_name}'."
        )
        return None

    input_cost_per_million = pricing.get("input_cost_per_million")
    output_cost_per_million = pricing.get("output_cost_per_million")

    if input_cost_per_million is None or output_cost_per_million is None:
        logger.error(
            f"Incomplete pricing data for model: {model_name}"
        )
        return None

    try:
        # Calculate cost
        input_cost = (input_tokens / 1_000_000) * input_cost_per_million
        output_cost = (output_tokens / 1_000_000) * output_cost_per_million
        total_cost = input_cost + output_cost

        logger.debug(
            f"Estimated cost for {model_name} ({input_tokens} in, {output_tokens} out): ${total_cost:.6f}"
        )
        return total_cost

    except Exception as e:
        logger.error(
            f"Error calculating cost for model {model_name}: {e}", exc_info=True
        )
        return None