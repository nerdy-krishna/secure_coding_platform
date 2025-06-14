# src/app/llm/llm_client.py
import logging
import os
import json
from typing import Type, TypeVar, Optional, NamedTuple, Dict

from pydantic import BaseModel

from ..utils import cost_estimation
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
    """
    Standardized result object returned to the agents.
    This simplifies the interface for the agents, abstracting away the provider-specific result model.
    """

    raw_output: str
    parsed_output: Optional[BaseModel]
    error: Optional[str]
    cost: Optional[float]


class LLMClient:
    """
    A client for interacting with a configured Large Language Model.
    This class acts as a singleton.
    """

    _instance: Optional["LLMClient"] = None
    provider: LLMProvider

    def __new__(cls, *args, **kwargs) -> "LLMClient":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            provider_name = os.getenv("LLM_PROVIDER", "anthropic").lower()

            if provider_name == "openai":
                cls._instance.provider = OpenAIProvider()
            elif provider_name == "anthropic":
                cls._instance.provider = AnthropicProvider()
            elif provider_name == "google":
                cls._instance.provider = GoogleProvider()
            else:
                raise ValueError(f"Unsupported LLM provider: {provider_name}")

            logger.info(f"LLMClient initialized with provider: {provider_name}")

        return cls._instance

    def _extract_json_from_text(self, text: str) -> Optional[Dict]:
        """
        Extracts a JSON object from a string, even if it's embedded in other text.
        """
        try:
            json_start = text.find("{")
            if json_start == -1:
                return None

            brace_level = 0
            json_end = -1
            for i, char in enumerate(text[json_start:]):
                if char == "{":
                    brace_level += 1
                elif char == "}":
                    brace_level -= 1
                    if brace_level == 0:
                        json_end = json_start + i + 1
                        break

            if json_end == -1:
                return None

            json_str = text[json_start:json_end]
            return json.loads(json_str)

        except (json.JSONDecodeError, Exception) as e:
            logger.error(f"Could not extract or parse JSON from text: {e}")
            return None

    async def generate_structured_output(
        self, prompt: str, response_model: Type[T]
    ) -> "AgentLLMResult":
        """
        Generates a structured response from the LLM based on a Pydantic model.
        """
        model_schema = response_model.schema_json(indent=2)
        full_prompt = (
            f"{prompt}\n\n"
            f"Please provide your response in a JSON format that strictly follows this Pydantic schema:\n"
            f"```json\n{model_schema}\n```\n"
            f"Ensure the JSON is well-formed and complete."
        )

        provider_result: ProviderLLMResult = await self.provider.generate(full_prompt)

        if provider_result.status == "failed" or not provider_result.output_text:
            return AgentLLMResult(
                raw_output=provider_result.output_text or "",
                parsed_output=None,
                error=provider_result.error or "LLM generation failed with no output.",
                cost=cost_estimation.estimate_cost(
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
                cost=cost_estimation.estimate_cost(
                    provider_result.model_name or "",
                    provider_result.prompt_tokens or 0,
                    provider_result.completion_tokens or 0,
                ),
            )

        try:
            parsed_output = response_model.parse_obj(parsed_json)
            return AgentLLMResult(
                raw_output=raw_output_text,
                parsed_output=parsed_output,
                error=None,
                cost=cost_estimation.estimate_cost(
                    provider_result.model_name or "",
                    provider_result.prompt_tokens or 0,
                    provider_result.completion_tokens or 0,
                ),
            )
        except Exception as e:
            logger.error(
                f"Failed to parse LLM response into Pydantic model: {e}\nRaw JSON:\n{parsed_json}"
            )
            return AgentLLMResult(
                raw_output=raw_output_text,
                parsed_output=None,
                error=f"Pydantic validation failed: {e}",
                cost=cost_estimation.estimate_cost(
                    provider_result.model_name or "",
                    provider_result.prompt_tokens or 0,
                    provider_result.completion_tokens or 0,
                ),
            )


def get_llm_client() -> LLMClient:
    """Factory function to get the singleton instance of LLMClient."""
    return LLMClient()
