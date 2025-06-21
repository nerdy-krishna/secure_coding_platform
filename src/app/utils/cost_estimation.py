# src/app/utils/cost_estimation.py

import logging
from typing import Dict

import tiktoken

# Import the database model to use for type hinting
from app.db import models as db_models

logger = logging.getLogger(__name__)


def count_tokens(text: str, tokenizer_encoding: str) -> int:
    """
    Counts the number of tokens in a text string using a dynamically provided
    tokenizer encoding name.
    """
    if not text or not tokenizer_encoding:
        return 0
    
    try:
        encoding = tiktoken.get_encoding(tokenizer_encoding)
    except ValueError:
        logger.warning(
            f"Encoding '{tokenizer_encoding}' not found. "
            "Falling back to default 'cl100k_base'."
        )
        encoding = tiktoken.get_encoding("cl100k_base")

    # The disallowed_special=() argument prevents errors with special tokens
    return len(encoding.encode(text, disallowed_special=()))


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
    input_cost = (input_tokens / 1_000_000) * config.input_cost_per_million

    # 2. Predict output tokens and calculate their estimated cost
    predicted_output_tokens = int(input_tokens * output_token_percentage)
    predicted_output_cost = (
        predicted_output_tokens / 1_000_000
    ) * config.output_cost_per_million

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
    input_cost = (prompt_tokens / 1_000_000) * config.input_cost_per_million
    output_cost = (completion_tokens / 1_000_000) * config.output_cost_per_million
    total_cost = input_cost + output_cost

    logger.info(
        f"Actual cost for {config.model_name} ({prompt_tokens} in, "
        f"{completion_tokens} out): ${total_cost:.6f}"
    )
    return total_cost