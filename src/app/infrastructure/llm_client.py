# src/app/infrastructure/llm_client.py

import logging
import uuid
import time
from typing import Type, TypeVar, Optional, NamedTuple, Any, Dict, cast

from pydantic import BaseModel, SecretStr
from app.infrastructure.database import AsyncSessionLocal as async_session_factory
from app.infrastructure.database.models import LLMConfiguration as DB_LLMConfiguration
from app.shared.lib import cost_estimation
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.llm_client_rate_limiter import get_rate_limiter_for_provider

# LangChain imports
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.callbacks.base import AsyncCallbackHandler
from langchain_core.outputs import LLMResult as LangChainLLMResult
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class TokenUsageCallbackHandler(AsyncCallbackHandler):
    """Callback handler to extract token usage."""
    def __init__(self, provider_name: str):
        super().__init__()
        self.provider_name = provider_name.lower()
        self.prompt_tokens: int = 0
        self.completion_tokens: int = 0
        self.total_tokens: int = 0

    async def on_llm_end(self, response: LangChainLLMResult, **kwargs: Any) -> None:
        """Collect token usage from the LLM response."""
        llm_output = response.llm_output if response.llm_output else {}
        
        if self.provider_name == "openai":
            token_usage = llm_output.get("token_usage", {})
            self.prompt_tokens = token_usage.get("prompt_tokens", 0)
            self.completion_tokens = token_usage.get("completion_tokens", 0)
            self.total_tokens = token_usage.get("total_tokens", 0)
        elif self.provider_name == "anthropic":
            usage_info = llm_output.get("usage", {}) 
            self.prompt_tokens = usage_info.get("input_tokens", 0)
            self.completion_tokens = usage_info.get("output_tokens", 0)
            if self.prompt_tokens and self.completion_tokens:
                self.total_tokens = self.prompt_tokens + self.completion_tokens
            elif self.prompt_tokens:
                self.total_tokens = self.prompt_tokens
        elif self.provider_name == "google":
            usage_metadata = llm_output.get("usage_metadata") or llm_output.get("token_usage") or {}
            self.prompt_tokens = usage_metadata.get("prompt_token_count") or usage_metadata.get("prompt_tokens") or 0
            self.completion_tokens = usage_metadata.get("candidates_token_count") or usage_metadata.get("completion_tokens") or 0
            self.total_tokens = usage_metadata.get("total_token_count") or usage_metadata.get("total_tokens") or (self.prompt_tokens + self.completion_tokens)

        logger.debug(
            f"TokenUsageCallback: Provider: {self.provider_name}, "
            f"Prompt: {self.prompt_tokens}, Completion: {self.completion_tokens}, Total: {self.total_tokens}"
        )


class AgentLLMResult(NamedTuple):
    raw_output: str
    parsed_output: Optional[BaseModel]
    error: Optional[str]
    cost: Optional[float]
    prompt_tokens: Optional[int]
    completion_tokens: Optional[int]
    total_tokens: Optional[int]
    latency_ms: Optional[int]


class LLMClient:
    """
    A client for interacting with a specific, configured Large Language Model
    using LangChain's structured output capabilities. This class is instantiated with a configuration object.
    """
    chat_model: BaseChatModel
    model_name_for_cost: str
    provider_name: str
    db_llm_config: DB_LLMConfiguration
    decrypted_api_key: str # ADDED: Store the key directly

    def __init__(self, llm_config: DB_LLMConfiguration):
        """
        Initializes the LLMClient with a specific configuration using LangChain models.
        """
        self.db_llm_config = llm_config
        self.provider_name = llm_config.provider.lower()
        decrypted_api_key = getattr(llm_config, 'decrypted_api_key', None)
        if not decrypted_api_key:
            raise ValueError(f"API key for LLM config {llm_config.id} is missing or not decrypted.")

        self.decrypted_api_key = decrypted_api_key # ADDED: Assign the key
        self.model_name_for_cost = llm_config.model_name

        if self.provider_name == "openai":
            self.chat_model = ChatOpenAI(api_key=SecretStr(self.decrypted_api_key), model=llm_config.model_name)
        elif self.provider_name == "anthropic":
            self.chat_model = ChatAnthropic(api_key=SecretStr(self.decrypted_api_key), model_name=llm_config.model_name, timeout=120, stop=None)
        elif self.provider_name == "google":
            self.chat_model = ChatGoogleGenerativeAI(google_api_key=SecretStr(self.decrypted_api_key), model=llm_config.model_name)
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider_name}")

        logger.info(f"LLMClient initialized with LangChain provider: {self.provider_name} for model {llm_config.model_name}")

    async def generate_structured_output(
        self, prompt: str, response_model: Type[T]
    ) -> "AgentLLMResult":
        """
        Generates structured output from the LLM, parsing it into the given Pydantic model.
        Uses LangChain's .with_structured_output() for robust parsing.
        Includes token usage and latency measurement via callbacks.
        """
        logger.info(
            "Entering LLM structured output generation.",
            extra={
                "model_name": self.db_llm_config.model_name,
                "provider": self.provider_name,
                "response_model": response_model.__name__,
            },
        )

        # Acquire a permit from the provider-specific rate limiter
        rate_limiter = get_rate_limiter_for_provider(self.provider_name)
        if rate_limiter:
            # First, count tokens for the prompt to pass to the limiter
            prompt_tokens = cost_estimation.count_tokens(
                prompt, self.db_llm_config
            )
            await rate_limiter.acquire(tokens=prompt_tokens)
        
        structured_llm = self.chat_model.with_structured_output(response_model)
        token_callback = TokenUsageCallbackHandler(provider_name=self.provider_name)
        
        start_time = time.perf_counter()
        parsed_output_value: Optional[T] = None
        error_message: Optional[str] = None

        try:
            invoked_result = cast(T, await structured_llm.ainvoke(
                prompt, config={"callbacks": [token_callback]}
            ))
            parsed_output_value = invoked_result
        except Exception as e:
            logger.error(f"LLM generation or parsing with LangChain failed: {e}", exc_info=True)
            error_message = str(e)
        
        end_time = time.perf_counter()
        latency_ms = int((end_time - start_time) * 1000)

        cost = cost_estimation.calculate_actual_cost(
            config=self.db_llm_config,
            prompt_tokens=token_callback.prompt_tokens,
            completion_tokens=token_callback.completion_tokens,
        )

        return AgentLLMResult(
            raw_output="[Structured output - raw text not directly available]",
            parsed_output=parsed_output_value,
            error=error_message,
            cost=cost,
            prompt_tokens=token_callback.prompt_tokens,
            completion_tokens=token_callback.completion_tokens,
            total_tokens=token_callback.total_tokens,
            latency_ms=latency_ms,
        )


async def get_llm_client(llm_config_id: uuid.UUID) -> Optional[LLMClient]:
    """
    Factory function to get an instance of LLMClient for a specific config ID.
    This is the new entry point for agents.
    """
    logger.info("Attempting to get LLM client for config ID.", extra={"llm_config_id": str(llm_config_id)})
    async with async_session_factory() as db:
        repo = LLMConfigRepository(db)
        llm_config = await repo.get_by_id_with_decrypted_key(llm_config_id)
        if not llm_config:
            logger.error(f"Could not find LLM configuration with ID: {llm_config_id}", extra={"llm_config_id": str(llm_config_id)})
            return None
        
        logger.info("Successfully retrieved LLM config and returning new LLMClient instance.", extra={"llm_config_id": str(llm_config_id)})
        return LLMClient(llm_config=llm_config)