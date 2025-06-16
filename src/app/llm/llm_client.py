# src/app/llm/llm_client.py
import logging
import uuid
import time # For latency measurement
from typing import Type, TypeVar, Optional, NamedTuple, Any, Dict, cast

from pydantic import BaseModel
from app.db import crud
from app.db.database import AsyncSessionLocal as async_session_factory
from app.db.models import LLMConfiguration as DB_LLMConfiguration
from app.utils import cost_estimation

# LangChain imports
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.callbacks.base import AsyncCallbackHandler
from langchain_core.outputs import LLMResult as LangChainLLMResult # For callback type hinting
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
        # llm_output is a dictionary that might contain token usage.
        # The structure of llm_output can vary between LLM providers.
        llm_output = response.llm_output if response.llm_output else {}
        
        if self.provider_name == "openai":
            token_usage = llm_output.get("token_usage", {})
            self.prompt_tokens = token_usage.get("prompt_tokens", 0)
            self.completion_tokens = token_usage.get("completion_tokens", 0)
            self.total_tokens = token_usage.get("total_tokens", 0)
        elif self.provider_name == "anthropic":
            # Anthropic's usage might be nested differently or have different key names
            # This is a common structure, adjust if necessary based on actual response
            usage_info = llm_output.get("usage", {}) 
            self.prompt_tokens = usage_info.get("input_tokens", 0)
            self.completion_tokens = usage_info.get("output_tokens", 0)
            if self.prompt_tokens and self.completion_tokens:
                self.total_tokens = self.prompt_tokens + self.completion_tokens
            elif self.prompt_tokens: # If only prompt tokens are available
                self.total_tokens = self.prompt_tokens
        elif self.provider_name == "google":
            usage_metadata = llm_output.get("usage_metadata", {})
            self.prompt_tokens = usage_metadata.get("prompt_token_count", 0)
            # Google often provides "candidates_token_count" for completion
            self.completion_tokens = usage_metadata.get("candidates_token_count", 0)
            self.total_tokens = usage_metadata.get("total_token_count", 0)
            # If total_token_count is missing but others are present
            if not self.total_tokens and self.prompt_tokens and self.completion_tokens:
                 self.total_tokens = self.prompt_tokens + self.completion_tokens

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
    using LangChain's structured output capabilities.
    This class is instantiated with a configuration object.
    """
    chat_model: BaseChatModel
    model_name_for_cost: str
    provider_name: str # To help callback handler

    def __init__(self, llm_config: DB_LLMConfiguration):
        """
        Initializes the LLMClient with a specific configuration using LangChain models.
        """
        self.provider_name = llm_config.provider.lower()
        decrypted_api_key = getattr(llm_config, 'decrypted_api_key', None)
        if not decrypted_api_key:
            raise ValueError(f"API key for LLM config {llm_config.id} is missing or not decrypted.")

        self.model_name_for_cost = llm_config.model_name

        if self.provider_name == "openai":
            self.chat_model = ChatOpenAI(api_key=decrypted_api_key, model=llm_config.model_name)
        elif self.provider_name == "anthropic":
            self.chat_model = ChatAnthropic(api_key=decrypted_api_key, model_name=llm_config.model_name, timeout=120, stop=None)
        elif self.provider_name == "google":
            self.chat_model = ChatGoogleGenerativeAI(google_api_key=decrypted_api_key, model=llm_config.model_name)
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
        logger.debug(f"Generating structured output for model: {self.model_name_for_cost}, response_model: {response_model.__name__}")
        
        structured_llm = self.chat_model.with_structured_output(response_model)
        token_callback = TokenUsageCallbackHandler(provider_name=self.provider_name)
        
        start_time = time.perf_counter()
        parsed_output_value: Optional[T] = None # Renamed for clarity, holds the final Optional[T]
        error_message: Optional[str] = None

        try:
            # Use cast to assure Pylance of the type returned by ainvoke
            invoked_result = cast(T, await structured_llm.ainvoke(
                prompt, config={"callbacks": [token_callback]}
            ))
            parsed_output_value = invoked_result
        except Exception as e:
            logger.error(f"LLM generation or parsing with LangChain failed: {e}", exc_info=True)
            error_message = str(e)
        
        end_time = time.perf_counter()
        latency_ms = int((end_time - start_time) * 1000)

        cost = cost_estimation.calculate_cost(
            model_name=self.model_name_for_cost,
            input_tokens=token_callback.prompt_tokens,
            output_tokens=token_callback.completion_tokens,
        )

        return AgentLLMResult(
            raw_output="[Structured output - raw text not directly available]",
            parsed_output=parsed_output_value, # Use the correctly typed variable
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
    async with async_session_factory() as db:
        llm_config = await crud.get_llm_config_with_decrypted_key(db, llm_config_id)
        if not llm_config:
            logger.error(f"Could not find LLM configuration with ID: {llm_config_id}")
            return None
        return LLMClient(llm_config=llm_config)
