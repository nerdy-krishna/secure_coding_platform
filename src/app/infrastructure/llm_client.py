# src/app/infrastructure/llm_client.py
#
# Node-level LLM client. Structured output goes through Pydantic AI (1.86)
# for validation-with-retry, typed output, and unified usage accounting
# across OpenAI / Anthropic / Google. This replaced a LangChain
# `with_structured_output` path in Phase I.3; LangChain is no longer
# imported here.
#
# Responsibilities that remain identical to the previous implementation:
# - honour the per-provider rate limiter (token-based budget).
# - run cost math against LiteLLM via the cost_estimation module.
# - preserve Anthropic prompt caching (cache_read / cache_write) by
#   marking the system prompt as cacheable on Anthropic models.
# - return an AgentLLMResult NamedTuple so existing call sites don't
#   change.

import logging
import time
import uuid
from typing import Any, NamedTuple, Optional, Type, TypeVar

from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.models.anthropic import AnthropicModel
from pydantic_ai.models.google import GoogleModel
from pydantic_ai.models.openai import OpenAIModel
from pydantic_ai.providers.anthropic import AnthropicProvider
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.providers.openai import OpenAIProvider

from app.infrastructure.database import AsyncSessionLocal as async_session_factory
from app.infrastructure.database.models import LLMConfiguration as DB_LLMConfiguration
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.llm_client_rate_limiter import get_rate_limiter_for_provider
from app.shared.lib import cost_estimation

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


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


# How many auto-retries Pydantic AI gets to recover a Pydantic-validation
# failure on the LLM output before we surface an error. Two is enough to
# absorb one bad sample; more burns cost without improving success rates
# meaningfully against current models.
_OUTPUT_RETRIES = 2


class LLMClient:
    """A client for a specific LLM configuration.

    Instantiated per call site; instances are not intended to be shared
    across concurrent callers (the Pydantic AI Agent construction is
    cheap, and keeping it per-call lets us set system_prompt with
    cache_control correctly for Anthropic).
    """

    provider_name: str
    db_llm_config: DB_LLMConfiguration
    decrypted_api_key: str

    def __init__(self, llm_config: DB_LLMConfiguration):
        self.db_llm_config = llm_config
        self.provider_name = llm_config.provider.lower()
        decrypted_api_key = getattr(llm_config, "decrypted_api_key", None)
        if not decrypted_api_key:
            raise ValueError(
                f"API key for LLM config {llm_config.id} is missing or not decrypted."
            )
        self.decrypted_api_key = decrypted_api_key
        logger.info(
            "LLMClient initialized for provider=%s model=%s",
            self.provider_name,
            llm_config.model_name,
        )

    # ------------------------------------------------------------------
    # Model construction — one factory per provider. Pydantic AI picks
    # the native structured-output strategy (tool-calling on OpenAI /
    # Anthropic, responseMimeType+schema on Google) based on the model.
    # ------------------------------------------------------------------

    def _build_model(self) -> Any:
        model_name = self.db_llm_config.model_name
        if self.provider_name == "openai":
            return OpenAIModel(
                model_name,
                provider=OpenAIProvider(api_key=self.decrypted_api_key),
            )
        if self.provider_name == "anthropic":
            return AnthropicModel(
                model_name,
                provider=AnthropicProvider(api_key=self.decrypted_api_key),
            )
        if self.provider_name == "google":
            return GoogleModel(
                model_name,
                provider=GoogleProvider(api_key=self.decrypted_api_key),
            )
        raise ValueError(f"Unsupported LLM provider: {self.provider_name}")

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def generate_structured_output(
        self,
        prompt: str,
        response_model: Type[T],
        system_prompt: Optional[str] = None,
    ) -> AgentLLMResult:
        """Run `prompt` through the configured LLM and validate the
        response against `response_model`. Pydantic AI automatically
        retries the LLM (up to `_OUTPUT_RETRIES`) if the first response
        fails Pydantic validation.

        Returns an `AgentLLMResult` even on failure — callers branch on
        `result.parsed_output` / `result.error`.
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

        # Pre-count tokens for the rate limiter's token budget. Cheap,
        # local call via LiteLLM (no network round-trip under
        # LITELLM_LOCAL_MODEL_COST_MAP=True).
        rate_limiter = get_rate_limiter_for_provider(self.provider_name)
        prompt_tokens_for_budget: Optional[int] = None
        if rate_limiter:
            prompt_tokens_for_budget = await cost_estimation.count_tokens(
                full_prompt_for_counting, self.db_llm_config
            )
            await rate_limiter.acquire(tokens=prompt_tokens_for_budget)

        model = self._build_model()

        # Build the agent. Pydantic AI's `system_prompt=` argument is
        # the stable prefix; when the underlying provider is Anthropic,
        # Pydantic AI serialises it with cache_control on the Messages
        # API, preserving our prompt-cache savings from Phase C.
        agent_kwargs: dict[str, Any] = {
            "output_type": response_model,
            "retries": _OUTPUT_RETRIES,
        }
        if system_prompt:
            agent_kwargs["system_prompt"] = system_prompt
        agent: Agent = Agent(model, **agent_kwargs)

        logger.debug(
            "LLM PROMPT [%s/%s]:\n%s\n---END PROMPT---",
            self.provider_name,
            self.db_llm_config.model_name,
            full_prompt_for_counting,
        )

        start_time = time.perf_counter()
        parsed_output_value: Optional[T] = None
        error_message: Optional[str] = None
        prompt_tokens: int = 0
        completion_tokens: int = 0
        cache_write_tokens: int = 0
        cache_read_tokens: int = 0

        try:
            run_result = await agent.run(prompt)
            parsed_output_value = run_result.output  # type: ignore[assignment]
            usage = run_result.usage()
            prompt_tokens = int(usage.input_tokens or 0)
            completion_tokens = int(usage.output_tokens or 0)
            cache_write_tokens = int(getattr(usage, "cache_write_tokens", 0) or 0)
            cache_read_tokens = int(getattr(usage, "cache_read_tokens", 0) or 0)
        except Exception as e:
            logger.error(
                "Pydantic AI run failed (provider=%s, model=%s): %s",
                self.provider_name,
                self.db_llm_config.model_name,
                e,
                exc_info=True,
            )
            error_message = str(e)

        end_time = time.perf_counter()
        latency_ms = int((end_time - start_time) * 1000)

        # Fill in the blanks if the provider didn't report usage. LiteLLM
        # gives us local tokenization; fall back to what we counted for
        # the rate limiter, then a len/4 last resort.
        if not prompt_tokens:
            prompt_tokens = prompt_tokens_for_budget or (
                len(full_prompt_for_counting) // 4
            )
        if not completion_tokens and parsed_output_value is not None:
            try:
                completion_tokens = len(parsed_output_value.model_dump_json()) // 4
            except Exception:  # pragma: no cover — defensive
                completion_tokens = 0

        if parsed_output_value is None and not error_message:
            error_message = (
                "LLM returned no parseable structured output. "
                f"Check that model name '{self.db_llm_config.model_name}' "
                f"is valid for provider '{self.provider_name}'."
            )
            logger.error(error_message)

        if parsed_output_value is not None:
            logger.debug(
                "LLM RESPONSE [%s/%s]:\n%s\n---END RESPONSE---",
                self.provider_name,
                self.db_llm_config.model_name,
                parsed_output_value,
            )

        cost = cost_estimation.calculate_actual_cost(
            config=self.db_llm_config,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )

        return AgentLLMResult(
            raw_output="[Structured output — raw text not directly available]",
            parsed_output=parsed_output_value,
            error=error_message,
            cost=cost,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            latency_ms=latency_ms,
            cache_creation_tokens=cache_write_tokens,
            cache_read_tokens=cache_read_tokens,
        )


async def get_llm_client(llm_config_id: uuid.UUID) -> Optional[LLMClient]:
    """Factory that resolves the DB config, decrypts its API key, and
    returns an LLMClient ready to run. The repo attaches the decrypted
    key to the ORM instance as a dynamic attribute — LLMClient reads it
    from there."""
    logger.info(
        "Attempting to get LLM client for config ID.",
        extra={"llm_config_id": str(llm_config_id)},
    )
    async with async_session_factory() as db:
        repo = LLMConfigRepository(db)
        config = await repo.get_by_id_with_decrypted_key(llm_config_id)
    if config is None:
        logger.error("LLM config %s not found.", llm_config_id)
        return None
    if not getattr(config, "decrypted_api_key", None):
        logger.error("Failed to decrypt API key for LLM config %s.", llm_config_id)
        return None

    logger.info(
        "Successfully retrieved LLM config and returning new LLMClient instance."
    )
    return LLMClient(config)
