# src/app/llm/llm_client.py
import logging
import json
import uuid
from typing import Type, TypeVar, Optional, NamedTuple, Dict, Any

from pydantic import BaseModel
from app.db import crud
from app.db.database import AsyncSessionLocal as async_session_factory # Corrected import
from app.db.models import LLMConfiguration as DB_LLMConfiguration
from app.utils import cost_estimation
from .providers import (
    AnthropicProvider,
    OpenAIProvider,
    GoogleProvider,
    LLMProvider,
    LLMResult as ProviderLLMResult,
)

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class AgentLLMResult(NamedTuple):
    raw_output: str
    parsed_output: Optional[BaseModel]
    error: Optional[str]
    cost: Optional[float]


class LLMClient:
    """
    A client for interacting with a specific, configured Large Language Model.
    This class is instantiated with a configuration object.
    """
    provider: LLMProvider

    def __init__(self, llm_config: DB_LLMConfiguration):
        """
        Initializes the LLMClient with a specific configuration.
        """
        provider_name = llm_config.provider.lower()
        # The key is decrypted and passed in via the config object
        decrypted_api_key = getattr(llm_config, 'decrypted_api_key', None)
        if not decrypted_api_key:
            raise ValueError(f"API key for LLM config {llm_config.id} is missing or not decrypted.")

        model_name = llm_config.model_name

        if provider_name == "openai":
            self.provider = OpenAIProvider(api_key=decrypted_api_key, model_name=model_name)
        elif provider_name == "anthropic":
            self.provider = AnthropicProvider(api_key=decrypted_api_key, model_name=model_name)
        elif provider_name == "google":
            self.provider = GoogleProvider(api_key=decrypted_api_key, model_name=model_name)
        else:
            raise ValueError(f"Unsupported LLM provider: {provider_name}")

        logger.info(f"LLMClient initialized with provider: {provider_name} for model {model_name}")

    def _extract_json_from_text(self, text: str) -> Optional[Dict]:
        # This utility function remains the same
        try:
            # Look for the first '{' to start, and the last '}' to end
            json_start = text.find("{")
            json_end = text.rfind("}")
            if json_start == -1 or json_end == -1 or json_end < json_start:
                return None
            
            json_str = text[json_start : json_end + 1]
            return json.loads(json_str)
        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"Could not extract or parse JSON from text: {e}")
            return None

    async def generate_structured_output(
        self, prompt: str, response_model: Type[T]
    ) -> "AgentLLMResult":
        # This core logic function remains the same
        model_schema = response_model.model_json_schema()
        full_prompt = (
            f"{prompt}\n\n"
            f"Please provide your response in a JSON format that strictly follows this Pydantic schema:\n"
            f"```json\n{json.dumps(model_schema, indent=2)}\n```\n"
            f"Ensure the JSON is well-formed and complete."
        )

        provider_result: ProviderLLMResult = await self.provider.generate(full_prompt)

        if provider_result.status == "failed" or not provider_result.output_text:
            return AgentLLMResult(
                raw_output=provider_result.output_text or "",
                parsed_output=None,
                error=provider_result.error or "LLM generation failed with no output.",
                cost=cost_estimation.calculate_cost(
                    provider_result.model_name or "",
                    provider_result.prompt_tokens or 0,
                    provider_result.completion_tokens or 0,
                ),
            )

        raw_output_text = provider_result.output_text
        parsed_json = self._extract_json_from_text(raw_output_text)

        if parsed_json is None:
            return AgentLLMResult(
                raw_output=raw_output_text,
                parsed_output=None,
                error="Failed to extract a valid JSON object from the LLM response.",
                cost=cost_estimation.calculate_cost(
                    provider_result.model_name or "",
                    provider_result.prompt_tokens or 0,
                    provider_result.completion_tokens or 0,
                ),
            )

        try:
            parsed_output = response_model.model_validate(parsed_json)
            return AgentLLMResult(
                raw_output=raw_output_text,
                parsed_output=parsed_output,
                error=None,
                cost=cost_estimation.calculate_cost(
                    provider_result.model_name or "",
                    provider_result.prompt_tokens or 0,
                    provider_result.completion_tokens or 0,
                ),
            )
        except Exception as e:
            logger.error(f"Failed to parse LLM response into Pydantic model: {e}\nRaw JSON:\n{parsed_json}")
            return AgentLLMResult(
                raw_output=raw_output_text,
                parsed_output=None,
                error=f"Pydantic validation failed: {e}",
                cost=cost_estimation.calculate_cost(
                    provider_result.model_name or "",
                    provider_result.prompt_tokens or 0,
                    provider_result.completion_tokens or 0,
                ),
            )


async def get_llm_client(llm_config_id: uuid.UUID) -> Optional[LLMClient]:
    """
    Factory function to get an instance of LLMClient for a specific config ID.
    This is the new entry point for agents.
    """
    async with async_session_factory() as db:
        llm_config = await crud.get_llm_config_with_decrypted_key(db, llm_config_id)
        if not llm_config:
            logger.error(f"Could not find LLM configuration with ID: {llm_config_id}")
            return None
        return LLMClient(llm_config=llm_config)
