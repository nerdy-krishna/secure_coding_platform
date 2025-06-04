import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)

# --- Define Model Costs ---
# Prices per Million tokens. Update these with current pricing from your LLM provider.
# Example for gpt-4o-mini (as of mid-2024, always verify current rates)
# For Google Gemini, you'd add its pricing structure similarly if you want to estimate its costs.
MODEL_PRICING: Dict[str, Dict[str, float]] = {
    "gpt-4o-mini": {  # Example, ensure this key matches model names used
        "input_cost_per_million": 0.15,
        "output_cost_per_million": 0.60,
    },
    "gpt-4o-mini-2024-07-18": {  # As used in your providers.py
        "input_cost_per_million": 0.15,
        "output_cost_per_million": 0.60,
    },
    "gpt-4o": {  # Example for a larger model
        "input_cost_per_million": 5.00,
        "output_cost_per_million": 15.00,
    },
    "gpt-4-turbo": {
        "input_cost_per_million": 10.00,
        "output_cost_per_million": 30.00,
    },
    "gemini-1.5-flash-latest": {  # Example for Gemini - **VERIFY ACTUAL PRICING**
        "input_cost_per_million": 0.35,  # Placeholder - check official Google Cloud/AI pricing
        "output_cost_per_million": 1.05,  # Placeholder - check official Google Cloud/AI pricing
    },
    # Add other models as needed, ensuring keys match model names used by LLM clients
}


def estimate_openai_cost(  # Renamed to be more generic if you add other providers
    model_name: Optional[str],
    input_tokens: Optional[int],
    output_tokens: Optional[int],
) -> Optional[float]:
    """
    Estimates the cost of an LLM API call based on model and token counts.
    Args:
        model_name: The name of the LLM model used.
        input_tokens: The number of input tokens consumed.
        output_tokens: The number of output tokens generated.
    Returns:
        The estimated cost in USD, or None if pricing info is missing or calculation fails.
    """
    if not model_name or input_tokens is None or output_tokens is None:
        # Allow zero tokens, as some calls might not have one or the other (e.g. pure completion with no input tokens logged)
        if not model_name or input_tokens is None or output_tokens is None:
            logger.warning(
                f"Missing model name ({model_name}) or token counts (input: {input_tokens}, output: {output_tokens}) for cost estimation."
            )
            return None

    # Normalize model name if needed (e.g. remove date suffixes if base model pricing applies)
    # For now, assumes exact match or that variations are listed in MODEL_PRICING
    pricing_key = model_name
    if model_name not in MODEL_PRICING:
        # Try to find a base model key (e.g., "gpt-4o-mini" from "gpt-4o-mini-2024-07-18")
        base_model_key = (
            model_name.split("-")[0] + "-" + model_name.split("-")[1]
            if len(model_name.split("-")) > 2
            else None
        )
        if base_model_key and base_model_key in MODEL_PRICING:
            pricing_key = base_model_key
            logger.debug(
                f"Using base model pricing key '{pricing_key}' for model '{model_name}'."
            )
        else:
            logger.warning(
                f"Pricing information not found for model: {model_name} or its potential base '{base_model_key}'. Cost will be None."
            )
            return None

    pricing = MODEL_PRICING.get(pricing_key)
    if not pricing:  # Should be caught by the above, but as a safeguard
        logger.warning(
            f"Pricing information still not found for effective pricing key: {pricing_key} (original model: {model_name})"
        )
        return None

    input_cost_per_million = pricing.get("input_cost_per_million")
    output_cost_per_million = pricing.get("output_cost_per_million")

    if input_cost_per_million is None or output_cost_per_million is None:
        logger.error(
            f"Incomplete pricing data (input/output cost per million) for model: {pricing_key}"
        )
        return None

    try:
        # Ensure tokens are treated as 0 if None for calculation, though earlier check should prevent this
        calc_input_tokens = input_tokens if input_tokens is not None else 0
        calc_output_tokens = output_tokens if output_tokens is not None else 0

        input_cost = (calc_input_tokens / 1_000_000) * input_cost_per_million
        output_cost = (calc_output_tokens / 1_000_000) * output_cost_per_million
        total_cost = input_cost + output_cost

        logger.debug(
            f"Estimated cost for {model_name} ({calc_input_tokens} in, {calc_output_tokens} out): ${total_cost:.6f}"
        )
        return total_cost

    except Exception as e:
        logger.error(
            f"Error calculating cost for model {model_name}: {e}", exc_info=True
        )
        return None
