# src/app/llm/providers.py
import os
import logging
import time
from abc import ABC, abstractmethod
from pydantic import BaseModel, SecretStr
from typing import Optional, Dict, Any

# LangChain specific imports
from langchain_openai import ChatOpenAI
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_anthropic import ChatAnthropic  # Added for Anthropic
from langchain_core.messages import HumanMessage

from dotenv import load_dotenv

logger = logging.getLogger(__name__)
load_dotenv()


class LLMResult(BaseModel):
    output_text: Optional[str] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    model_name: Optional[str] = None
    latency_ms: Optional[int] = None
    error: Optional[str] = None
    status: str = "success"


class LLMProvider(ABC):
    @abstractmethod
    async def generate(
        self, prompt: str, generation_config_override: Optional[Dict[str, Any]] = None
    ) -> LLMResult:
        pass


class OpenAIProvider(LLMProvider):
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.model_name = os.getenv("OPENAI_MODEL_NAME", "gpt-4o-mini")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set.")
        try:
            self.client = ChatOpenAI(
                api_key=SecretStr(self.api_key), model=self.model_name
            )
            logger.info(f"Initialized OpenAIProvider with model: {self.model_name}")
        except Exception as e:
            logger.error(f"Failed to initialize ChatOpenAI client: {e}")
            raise

    async def generate(
        self, prompt: str, generation_config_override: Optional[Dict[str, Any]] = None
    ) -> LLMResult:
        logger.debug(
            f"OpenAIProvider sending prompt (first 50 chars): '{prompt[:50]}...'"
        )
        message = HumanMessage(content=prompt)
        start_time = time.perf_counter()
        result = LLMResult(model_name=self.model_name)

        try:
            llm_with_overrides = self.client
            if generation_config_override:
                llm_with_overrides = self.client.bind(**generation_config_override)
                logger.info(
                    f"Using generation_config override: {generation_config_override}"
                )

            response = await llm_with_overrides.ainvoke([message])
            end_time = time.perf_counter()
            result.latency_ms = int((end_time - start_time) * 1000)
            result.output_text = str(response.content)

            if (
                hasattr(response, "response_metadata")
                and "token_usage" in response.response_metadata
            ):
                token_usage = response.response_metadata["token_usage"]
                result.prompt_tokens = token_usage.get("prompt_tokens")
                result.completion_tokens = token_usage.get("completion_tokens")
                result.total_tokens = token_usage.get("total_tokens")

            result.status = "success"

        except Exception as e:
            end_time = time.perf_counter()
            result.latency_ms = int((end_time - start_time) * 1000)
            logger.error(f"Error during OpenAI API call: {e}", exc_info=True)
            result.error = f"LLM generation failed: {str(e)}"
            result.status = "failed"
            result.output_text = f"Error: {str(e)}"

        return result


# Renamed from GoogleGeminiProvider for consistency
class GoogleProvider(LLMProvider):
    def __init__(self):
        self.api_key = os.getenv("GOOGLE_API_KEY")
        self.model_name = os.getenv("GOOGLE_MODEL_NAME", "gemini-1.5-flash-latest")
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY environment variable not set.")
        try:
            self.client = ChatGoogleGenerativeAI(
                model=self.model_name,
                google_api_key=self.api_key,
            )
            logger.info(f"Initialized GoogleProvider with model: {self.model_name}")
        except Exception as e:
            logger.error(f"Failed to initialize ChatGoogleGenerativeAI client: {e}")
            raise

    async def generate(
        self, prompt: str, generation_config_override: Optional[Dict[str, Any]] = None
    ) -> LLMResult:
        logger.debug(
            f"GoogleProvider sending prompt (first 50 chars): '{prompt[:50]}...'"
        )
        message = HumanMessage(content=prompt)
        start_time = time.perf_counter()
        result = LLMResult(model_name=self.model_name)

        try:
            llm_with_overrides = self.client
            if generation_config_override:
                llm_with_overrides = self.client.bind(**generation_config_override)
                logger.info(
                    f"Using generation_config override: {generation_config_override}"
                )

            response = await llm_with_overrides.ainvoke([message])
            end_time = time.perf_counter()
            result.latency_ms = int((end_time - start_time) * 1000)
            result.output_text = str(response.content)

            if (
                hasattr(response, "response_metadata")
                and "usage_metadata" in response.response_metadata
            ):
                usage_metadata = response.response_metadata["usage_metadata"]
                result.prompt_tokens = usage_metadata.get("prompt_token_count")
                result.completion_tokens = usage_metadata.get("candidates_token_count")
                result.total_tokens = usage_metadata.get("total_token_count")

            result.status = "success"

        except Exception as e:
            end_time = time.perf_counter()
            result.latency_ms = int((end_time - start_time) * 1000)
            logger.error(f"Error during Google Gemini API call: {e}", exc_info=True)
            result.error = f"LLM generation failed: {str(e)}"
            result.status = "failed"
            result.output_text = f"Error: {str(e)}"

        return result


# Added the missing AnthropicProvider, following the same LangChain pattern
class AnthropicProvider(LLMProvider):
    def __init__(self):
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.model_name = os.getenv("ANTHROPIC_MODEL_NAME", "claude-3-haiku-20240307")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set.")
        try:
            self.client = ChatAnthropic(api_key=self.api_key, model=self.model_name)
            logger.info(f"Initialized AnthropicProvider with model: {self.model_name}")
        except Exception as e:
            logger.error(f"Failed to initialize ChatAnthropic client: {e}")
            raise

    async def generate(
        self, prompt: str, generation_config_override: Optional[Dict[str, Any]] = None
    ) -> LLMResult:
        logger.debug(
            f"AnthropicProvider sending prompt (first 50 chars): '{prompt[:50]}...'"
        )
        message = HumanMessage(content=prompt)
        start_time = time.perf_counter()
        result = LLMResult(model_name=self.model_name)

        try:
            llm_with_overrides = self.client
            if generation_config_override:
                llm_with_overrides = self.client.bind(**generation_config_override)
                logger.info(
                    f"Using generation_config override: {generation_config_override}"
                )

            response = await llm_with_overrides.ainvoke([message])
            end_time = time.perf_counter()
            result.latency_ms = int((end_time - start_time) * 1000)
            result.output_text = str(response.content)

            if (
                hasattr(response, "response_metadata")
                and "usage" in response.response_metadata
            ):
                usage = response.response_metadata["usage"]
                result.prompt_tokens = usage.get("input_tokens")
                result.completion_tokens = usage.get("output_tokens")
                if result.prompt_tokens and result.completion_tokens:
                    result.total_tokens = (
                        result.prompt_tokens + result.completion_tokens
                    )

            result.status = "success"

        except Exception as e:
            end_time = time.perf_counter()
            result.latency_ms = int((end_time - start_time) * 1000)
            logger.error(f"Error during Anthropic API call: {e}", exc_info=True)
            result.error = f"LLM generation failed: {str(e)}"
            result.status = "failed"
            result.output_text = f"Error: {str(e)}"

        return result
