# src/app/infrastructure/llm_client.py

import json
import logging
import re
import uuid
import time
from typing import Tuple, Type, TypeVar, Optional, NamedTuple, Any, cast

from pydantic import BaseModel, SecretStr
from app.infrastructure.database import AsyncSessionLocal as async_session_factory
from app.infrastructure.database.models import LLMConfiguration as DB_LLMConfiguration
from app.shared.lib import cost_estimation
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.llm_client_rate_limiter import get_rate_limiter_for_provider

# LangChain imports
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.callbacks.base import AsyncCallbackHandler
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.outputs import LLMResult as LangChainLLMResult
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class TokenUsageCallbackHandler(AsyncCallbackHandler):
    """Callback handler to extract token usage.

    For Anthropic, also captures prompt-cache metrics when available:
    - cache_creation_input_tokens: tokens billed to *write* a new cache entry
    - cache_read_input_tokens: tokens served from cache (~90% cheaper)
    These show up when a call uses cache_control and Anthropic returns the
    usage block with the extended fields.
    """

    def __init__(self, provider_name: str):
        super().__init__()
        self.provider_name = provider_name.lower()
        self.prompt_tokens: int = 0
        self.completion_tokens: int = 0
        self.total_tokens: int = 0
        self.cache_creation_tokens: int = 0
        self.cache_read_tokens: int = 0

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
            self.cache_creation_tokens = usage_info.get(
                "cache_creation_input_tokens", 0
            )
            self.cache_read_tokens = usage_info.get("cache_read_input_tokens", 0)
            if self.prompt_tokens and self.completion_tokens:
                self.total_tokens = self.prompt_tokens + self.completion_tokens
            elif self.prompt_tokens:
                self.total_tokens = self.prompt_tokens
        elif self.provider_name == "google":
            usage_metadata = (
                llm_output.get("usage_metadata") or llm_output.get("token_usage") or {}
            )
            self.prompt_tokens = (
                usage_metadata.get("prompt_token_count")
                or usage_metadata.get("prompt_tokens")
                or 0
            )
            self.completion_tokens = (
                usage_metadata.get("candidates_token_count")
                or usage_metadata.get("completion_tokens")
                or 0
            )
            self.total_tokens = (
                usage_metadata.get("total_token_count")
                or usage_metadata.get("total_tokens")
                or (self.prompt_tokens + self.completion_tokens)
            )

        cache_note = ""
        if self.cache_creation_tokens or self.cache_read_tokens:
            cache_note = (
                f", CacheCreate: {self.cache_creation_tokens}, "
                f"CacheRead: {self.cache_read_tokens}"
            )
        logger.debug(
            f"TokenUsageCallback: Provider: {self.provider_name}, "
            f"Prompt: {self.prompt_tokens}, Completion: {self.completion_tokens}, "
            f"Total: {self.total_tokens}{cache_note}"
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
    cache_creation_tokens: int = 0
    cache_read_tokens: int = 0


class LLMClient:
    """
    A client for interacting with a specific, configured Large Language Model
    using LangChain's structured output capabilities. This class is instantiated with a configuration object.
    """

    chat_model: BaseChatModel
    model_name_for_cost: str
    provider_name: str
    db_llm_config: DB_LLMConfiguration
    decrypted_api_key: str  # ADDED: Store the key directly

    def __init__(self, llm_config: DB_LLMConfiguration):
        """
        Initializes the LLMClient with a specific configuration using LangChain models.
        """
        self.db_llm_config = llm_config
        self.provider_name = llm_config.provider.lower()
        decrypted_api_key = getattr(llm_config, "decrypted_api_key", None)
        if not decrypted_api_key:
            raise ValueError(
                f"API key for LLM config {llm_config.id} is missing or not decrypted."
            )

        self.decrypted_api_key = decrypted_api_key  # ADDED: Assign the key
        self.model_name_for_cost = llm_config.model_name

        if self.provider_name == "openai":
            self.chat_model = ChatOpenAI(
                api_key=SecretStr(self.decrypted_api_key), model=llm_config.model_name
            )
        elif self.provider_name == "anthropic":
            self.chat_model = ChatAnthropic(
                api_key=SecretStr(self.decrypted_api_key),
                model_name=llm_config.model_name,
                timeout=120,
                stop=None,
            )
        elif self.provider_name == "google":
            self.chat_model = ChatGoogleGenerativeAI(
                google_api_key=SecretStr(self.decrypted_api_key),
                model=llm_config.model_name,
            )
        else:
            raise ValueError(f"Unsupported LLM provider: {self.provider_name}")

        logger.info(
            f"LLMClient initialized with LangChain provider: {self.provider_name} for model {llm_config.model_name}"
        )

    async def generate_structured_output(
        self,
        prompt: str,
        response_model: Type[T],
        system_prompt: Optional[str] = None,
    ) -> "AgentLLMResult":
        """
        Generates structured output from the LLM.

        Parameters:
          prompt: The variable (per-call) portion of the input.
          response_model: The Pydantic model to parse the response into.
          system_prompt: Optional stable prefix (agent role + RAG context etc.).
            When provided and the provider is Anthropic, the prefix is sent as a
            SystemMessage with cache_control={"type": "ephemeral"}, enabling
            prompt-cache reads on subsequent calls with the same prefix
            (typically 70%+ cost reduction on repeated-agent-per-file scans).
            For non-Anthropic providers the prefix is simply concatenated
            ahead of `prompt` to preserve existing behavior.
        """
        logger.info(
            "Entering LLM structured output generation.",
            extra={
                "model_name": self.db_llm_config.model_name,
                "provider": self.provider_name,
                "response_model": response_model.__name__,
                "cacheable_prefix": bool(system_prompt),
            },
        )

        full_prompt_for_counting = (
            f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        )

        # Acquire a permit from the provider-specific rate limiter
        rate_limiter = get_rate_limiter_for_provider(self.provider_name)
        prompt_tokens: Optional[int] = None
        if rate_limiter:
            # First, count tokens for the prompt to pass to the limiter
            prompt_tokens = await cost_estimation.count_tokens(
                full_prompt_for_counting,
                self.db_llm_config,
                api_key=self.decrypted_api_key,
            )
            await rate_limiter.acquire(tokens=prompt_tokens)

        # Gemini's default `with_structured_output` uses function-calling,
        # which conflicts with prompts that explicitly ask the model to
        # "Respond ONLY with a valid JSON object" — Gemini emits text JSON
        # instead of a tool call, leaving LangChain to return None. Switch
        # Google to json_mode (responseMimeType=application/json + schema),
        # which matches our prompt style and the structured-output contract.
        if self.provider_name == "google":
            structured_llm = self.chat_model.with_structured_output(
                response_model, method="json_mode"
            )
        else:
            structured_llm = self.chat_model.with_structured_output(response_model)
        token_callback = TokenUsageCallbackHandler(provider_name=self.provider_name)

        start_time = time.perf_counter()
        parsed_output_value: Optional[T] = None
        error_message: Optional[str] = None

        # [DEBUG LOGGING]
        # This will only show up if the log level is set to DEBUG via the Admin API.
        logger.debug(
            f"LLM PROMPT [{self.provider_name}/{self.db_llm_config.model_name}]:\n"
            f"{full_prompt_for_counting}\n---END PROMPT---"
        )

        invoke_input = self._build_invoke_input(system_prompt, prompt)

        try:
            invoked_result = cast(
                T,
                await structured_llm.ainvoke(
                    invoke_input, config={"callbacks": [token_callback]}
                ),
            )
            parsed_output_value = invoked_result
        except Exception as e:
            logger.error(
                f"LLM generation or parsing with LangChain failed "
                f"(provider={self.provider_name}, "
                f"model={self.db_llm_config.model_name}): {e}",
                exc_info=True,
            )
            error_message = str(e)

        # Manual JSON fallback for Google.
        # `langchain-google-genai 2.1.5` with_structured_output parser
        # returns None for some newer / preview Gemini models even though
        # the raw response contains valid JSON matching the requested
        # schema. When that happens, retry against the raw chat model and
        # parse the content ourselves. (Also useful when a cheaper / newer
        # model doesn't wire up tool-calling yet.)
        if parsed_output_value is None and self.provider_name == "google":
            parsed_output_value, fallback_err = await self._google_json_fallback(
                response_model, invoke_input, token_callback
            )
            if parsed_output_value is not None:
                logger.info(
                    "Google structured-output fallback parsed raw JSON "
                    f"(model={self.db_llm_config.model_name})."
                )
                error_message = None
            elif fallback_err:
                error_message = fallback_err

        if parsed_output_value is None and not error_message:
            error_message = (
                "LLM returned no parseable structured output. "
                f"Check that model name "
                f"'{self.db_llm_config.model_name}' is valid for provider "
                f"'{self.provider_name}'."
            )
            logger.error(error_message)

        # [DEBUG LOGGING]
        if parsed_output_value:
            logger.debug(
                f"LLM RESPONSE [{self.provider_name}/{self.db_llm_config.model_name}]:\n{parsed_output_value}\n---END RESPONSE---"
            )
        elif error_message:
            logger.debug(f"LLM ERROR response [{self.provider_name}]: {error_message}")

        end_time = time.perf_counter()
        latency_ms = int((end_time - start_time) * 1000)

        # FIX: Ensure we have token usage even if callback failed to capture it (common with Google/OpenAI integrations)
        start_prompt_tokens = token_callback.prompt_tokens
        completion_tokens = token_callback.completion_tokens

        # Fallback for prompt tokens: use the ones calculated for rate limiting,
        # or a rough len/4 estimate as a last resort.
        if not start_prompt_tokens and prompt_tokens is not None:
            start_prompt_tokens = prompt_tokens
        elif not start_prompt_tokens:
            start_prompt_tokens = len(full_prompt_for_counting) // 4

        # Fallback for completion tokens: count from parsed output if available, or rough estimate
        if not completion_tokens:
            if parsed_output_value:
                # Best effort: dump model to json string and count
                try:
                    output_str = parsed_output_value.model_dump_json()
                    # We assume same encoding/cost as input for simplicity if we can't call API
                    # Or just use len/4 for speed/safety
                    completion_tokens = len(output_str) // 4
                except Exception:
                    completion_tokens = 0
            elif error_message:
                completion_tokens = 0

        cost = cost_estimation.calculate_actual_cost(
            config=self.db_llm_config,
            prompt_tokens=start_prompt_tokens,
            completion_tokens=completion_tokens,
        )

        return AgentLLMResult(
            raw_output="[Structured output - raw text not directly available]",
            parsed_output=parsed_output_value,
            error=error_message,
            cost=cost,
            prompt_tokens=start_prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=start_prompt_tokens + completion_tokens,
            latency_ms=latency_ms,
            cache_creation_tokens=token_callback.cache_creation_tokens,
            cache_read_tokens=token_callback.cache_read_tokens,
        )

    async def _google_json_fallback(
        self,
        response_model: Type[T],
        invoke_input: Any,
        token_callback: "TokenUsageCallbackHandler",
    ) -> Tuple[Optional[T], Optional[str]]:
        """Fallback for Google when with_structured_output returns None.

        Invokes the base chat model (no wrapper), extracts JSON from the raw
        content, validates it against `response_model`, and returns the
        parsed instance. Returns (None, error_message) if the fallback
        can't recover either.

        Used only for provider='google' because other providers either
        support with_structured_output reliably (OpenAI, Anthropic) or are
        unsupported here. Token usage from the callback populated during
        the original attempt is preserved — no double-counting.
        """
        try:
            raw = await self.chat_model.ainvoke(
                invoke_input, config={"callbacks": [token_callback]}
            )
        except Exception as e:
            return None, f"Google fallback ainvoke failed: {e}"

        content = getattr(raw, "content", None)
        if not isinstance(content, str) or not content.strip():
            return None, "Google fallback: raw response content was empty."

        # Some Gemini preview models wrap JSON in fenced code blocks or
        # stray prose. Pull out the first JSON object we can find.
        match = re.search(r"\{[\s\S]*\}", content)
        if not match:
            return (
                None,
                f"Google fallback: no JSON object found in raw content "
                f"(first 80 chars: {content[:80]!r}).",
            )

        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError as e:
            return None, f"Google fallback: JSON decode failed: {e}"

        try:
            return response_model.model_validate(data), None
        except Exception as e:
            return None, f"Google fallback: schema validation failed: {e}"

    def _build_invoke_input(self, system_prompt: Optional[str], prompt: str) -> Any:
        """Returns the input to pass to structured_llm.ainvoke().

        - Anthropic + non-empty system_prompt → [SystemMessage(cache_control),
          HumanMessage]. The SystemMessage content is a list of content blocks
          with cache_control={"type": "ephemeral"} on the text block so
          Anthropic's prompt cache can serve the prefix on subsequent calls.
        - All other cases → a single concatenated string (preserves pre-cache
          behavior and works uniformly across providers that don't support
          prompt caching the same way).
        """
        if system_prompt and self.provider_name == "anthropic":
            system_message = SystemMessage(
                content=[
                    {
                        "type": "text",
                        "text": system_prompt,
                        "cache_control": {"type": "ephemeral"},
                    }
                ]
            )
            return [system_message, HumanMessage(content=prompt)]

        if system_prompt:
            return f"{system_prompt}\n\n{prompt}"
        return prompt


async def get_llm_client(llm_config_id: uuid.UUID) -> Optional[LLMClient]:
    """
    Factory function to get an instance of LLMClient for a specific config ID.
    This is the new entry point for agents.
    """
    logger.info(
        "Attempting to get LLM client for config ID.",
        extra={"llm_config_id": str(llm_config_id)},
    )
    async with async_session_factory() as db:
        repo = LLMConfigRepository(db)
        llm_config = await repo.get_by_id_with_decrypted_key(llm_config_id)
        if not llm_config:
            logger.error(
                f"Could not find LLM configuration with ID: {llm_config_id}",
                extra={"llm_config_id": str(llm_config_id)},
            )
            return None

        logger.info(
            "Successfully retrieved LLM config and returning new LLMClient instance.",
            extra={"llm_config_id": str(llm_config_id)},
        )
        return LLMClient(llm_config=llm_config)
