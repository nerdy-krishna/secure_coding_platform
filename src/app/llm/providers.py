# src/app/llm/providers.py
import os
import logging
import time
from abc import ABC, abstractmethod
from pydantic import BaseModel
from typing import Optional, Dict, Any
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage
from langchain_core.exceptions import OutputParserException

# --- Google Gemini Imports (Updated) ---
import google.generativeai as genai # The new SDK is typically imported as 'genai'
# For safety settings, the new SDK might use slightly different import paths if needed,
# but often they are part of genai.types or directly on the model/client methods.
# We'll use what's available on genai.GenerativeModel directly for safety settings.
# from google.generativeai.types import HarmCategory, HarmBlockThreshold # This might still be valid or similar
from google.api_core.exceptions import GoogleAPIError


from dotenv import load_dotenv

logger = logging.getLogger(__name__)
load_dotenv()

class LLMResult(BaseModel):
    content: Optional[str] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    model_name: Optional[str] = None
    latency_ms: Optional[int] = None
    error: Optional[str] = None
    status: str = "success"

class LLMProvider(ABC):
    @abstractmethod
    async def generate(self, prompt: str, generation_config_override: Optional[Dict[str, Any]] = None) -> LLMResult:
        pass

class OpenAIProvider(LLMProvider):
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.model_name = os.getenv("OPENAI_MODEL_NAME", "gpt-4o-mini")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set for OpenAIProvider.")
        try:
            self.client = ChatOpenAI(api_key=self.api_key, model=self.model_name)
            logger.info(f"Initialized OpenAIProvider with model: {self.model_name}")
        except Exception as e:
            logger.error(f"Failed to initialize ChatOpenAI client: {e}")
            raise

    async def generate(self, prompt: str, generation_config_override: Optional[Dict[str, Any]] = None) -> LLMResult:
        # ... (OpenAIProvider implementation remains the same) ...
        logger.debug(f"OpenAIProvider sending prompt (first 50 chars): '{prompt[:50]}...'")
        message = HumanMessage(content=prompt)
        start_time = time.perf_counter()
        result = LLMResult(model_name=self.model_name)

        try:
            if generation_config_override:
                logger.warning("generation_config_override not directly applied to LangChain OpenAIProvider in this basic setup.")

            response = await self.client.ainvoke([message])
            end_time = time.perf_counter()
            result.latency_ms = int((end_time - start_time) * 1000)

            if isinstance(response.content, str):
                result.content = response.content
            else:
                logger.error(f"Unexpected response type from OpenAI: {type(response.content)}")
                result.content = str(response.content) if response.content is not None else ""

            if hasattr(response, "response_metadata") and isinstance(response.response_metadata, dict):
                token_usage = response.response_metadata.get("token_usage", {})
                result.input_tokens = token_usage.get("prompt_tokens") or token_usage.get("input_tokens")
                result.output_tokens = token_usage.get("completion_tokens") or token_usage.get("output_tokens")
                result.total_tokens = token_usage.get("total_tokens")
                if result.total_tokens is not None:
                    logger.debug(f"OpenAI Token Usage: Input={result.input_tokens}, Output={result.output_tokens}, Total={result.total_tokens}")
            result.status = "success"

        except OutputParserException as e:
            end_time = time.perf_counter()
            result.latency_ms = int((end_time - start_time) * 1000)
            logger.error(f"Failed to parse response from OpenAI: {e}")
            result.error = f"Parsing failed: {e}"
            result.status = "failed"
        except Exception as e:
            end_time = time.perf_counter()
            result.latency_ms = int((end_time - start_time) * 1000)
            logger.error(f"Error during OpenAI API call: {e}", exc_info=True)
            result.error = f"LLM generation failed: {e}"
            result.status = "failed"
        return result

class GoogleGeminiProvider(LLMProvider):
    def __init__(self):
        self.api_key = os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY environment variable not set for GoogleGeminiProvider.")

        genai.configure(api_key=self.api_key) # Configure the SDK

        self.model_name = os.getenv("GOOGLE_MODEL_NAME", "gemini-2.0-flash")

        # Default safety settings - adjust as needed
        # The new SDK might handle this slightly differently or have different enums
        # For now, let's prepare to pass them if needed.
        # Check google.generativeai.types for HarmCategory and HarmBlockThreshold if using older `google-generativeai`
        # For `google-genai`, safety settings are often part of GenerationConfig or directly on the model.
        # We'll set them if the structure is similar, otherwise they might be defaults.
        self.safety_settings = [
            {
                "category": "HARM_CATEGORY_HARASSMENT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE",
            },
            {
                "category": "HARM_CATEGORY_HATE_SPEECH",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE",
            },
            {
                "category": "HARM_CATEGORY_SEXUALLY_EXPLICIT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE",
            },
            {
                "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                "threshold": "BLOCK_MEDIUM_AND_ABOVE",
            },
        ]

        self.default_generation_config_dict = {
            "temperature": 0.7,
            "top_p": 1.0, # Default for gemini-flash based on some docs
            "top_k": 32,  # Example, adjust as needed
            # "candidate_count": 1, # Default
            # "max_output_tokens": 2048, # Example
        }

        try:
            # The new SDK uses genai.GenerativeModel(model_name)
            self.client = genai.GenerativeModel(
                model_name=self.model_name,
                # safety_settings can be passed here if the structure is compatible
                # generation_config can also be passed here
            )
            logger.info(f"Initialized GoogleGeminiProvider with model: {self.model_name} using 'google-genai' SDK.")
        except Exception as e:
            logger.error(f"Failed to initialize Google Gemini client (model: {self.model_name}) using 'google-genai' SDK: {e}")
            raise

    async def generate(self, prompt: str, generation_config_override: Optional[Dict[str, Any]] = None) -> LLMResult:
        logger.debug(f"GoogleGeminiProvider sending prompt (first 50 chars): '{prompt[:50]}...'")
        start_time = time.perf_counter()
        result = LLMResult(model_name=self.model_name)

        current_gen_config = self.default_generation_config_dict.copy()
        if generation_config_override:
            current_gen_config.update(generation_config_override)
            logger.info(f"Using generation_config: {current_gen_config}")

        try:
            response = await self.client.generate_content_async(
                prompt,
                generation_config=genai.types.GenerationConfig(**current_gen_config), # Pass as GenerationConfig object
                safety_settings=self.safety_settings # Pass safety settings
            )

            end_time = time.perf_counter()
            result.latency_ms = int((end_time - start_time) * 1000)

            # Accessing response text and handling potential blocks
            if response.parts:
                result.content = "".join(part.text for part in response.parts if hasattr(part, 'text'))
            elif response.candidates and response.candidates[0].content.parts: # Fallback for some response structures
                 result.content = "".join(part.text for part in response.candidates[0].content.parts if hasattr(part, 'text'))
            else:
                result.content = "" # Ensure content is not None

            # Handle blocked responses or other finish reasons
            if hasattr(response, 'prompt_feedback') and response.prompt_feedback and response.prompt_feedback.block_reason:
                block_reason_message = response.prompt_feedback.block_reason_message or "Blocked by safety settings"
                logger.warning(f"Google Gemini response blocked: {response.prompt_feedback.block_reason}. Message: {block_reason_message}")
                result.error = f"Response blocked: {block_reason_message}"
                result.status = "failed_blocked"
            elif hasattr(response, 'candidates') and response.candidates and response.candidates[0].finish_reason.name != "STOP":
                finish_reason_name = response.candidates[0].finish_reason.name
                if finish_reason_name != "MAX_TOKENS": # MAX_TOKENS might not be an error per se
                    logger.warning(f"Google Gemini generation finished with reason: {finish_reason_name}")
                    result.error = f"Generation stopped due to: {finish_reason_name}"
                    result.status = "failed"

            if not result.content and result.status == "success": # If no content but not explicitly blocked/failed
                logger.warning("Google Gemini response has no text content but was not explicitly blocked.")
                # result.error = "No text content in response" # Avoid overwriting block reason
                # result.status = "failed_empty"

            # Token counting
            if hasattr(response, 'usage_metadata') and response.usage_metadata:
                result.input_tokens = response.usage_metadata.prompt_token_count
                # For candidates_token_count, it's the sum for all candidates. If only one candidate, it's fine.
                result.output_tokens = response.usage_metadata.candidates_token_count 
                result.total_tokens = response.usage_metadata.total_token_count
                if result.total_tokens is not None:
                     logger.debug(f"Google Gemini Token Usage: Input={result.input_tokens}, Output={result.output_tokens}, Total={result.total_tokens}")
            else: # Try to count tokens manually if not available (less accurate)
                try:
                    count_input_response = await self.client.count_tokens_async(prompt)
                    result.input_tokens = count_input_response.total_tokens
                    if result.content:
                        count_output_response = await self.client.count_tokens_async(result.content)
                        result.output_tokens = count_output_response.total_tokens
                    if result.input_tokens and result.output_tokens:
                        result.total_tokens = result.input_tokens + result.output_tokens
                except Exception as count_e:
                    logger.warning(f"Could not manually count tokens for Gemini: {count_e}")


            if result.status == "success" and not result.error : # If it wasn't set to failed/blocked
                result.status = "success"

        except GoogleAPIError as e:
            end_time = time.perf_counter()
            result.latency_ms = int((end_time - start_time) * 1000)
            logger.error(f"Google Gemini API error: {e}", exc_info=True)
            result.error = f"Google API error: {e.message if hasattr(e, 'message') else str(e)}"
            result.status = "failed"
        except Exception as e:
            end_time = time.perf_counter()
            result.latency_ms = int((end_time - start_time) * 1000)
            logger.error(f"Error during Google Gemini API call: {e}", exc_info=True)
            result.error = f"LLM generation failed: {e}"
            result.status = "failed"

        return result