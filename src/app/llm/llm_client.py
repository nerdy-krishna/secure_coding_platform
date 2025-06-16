# src/app/llm/llm_client.py
# src/app/llm/llm_client.py
import logging
import uuid
from typing import Type, TypeVar, Optional, NamedTuple

from pydantic import BaseModel
from app.db import crud
from app.db.database import AsyncSessionLocal as async_session_factory
from app.db.models import LLMConfiguration as DB_LLMConfiguration
from app.utils import cost_estimation

# LangChain imports
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
# Note: Removed re and json imports as they are no longer needed by this client


logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


class AgentLLMResult(NamedTuple):
    raw_output: str
    parsed_output: Optional[BaseModel]
    error: Optional[str]
    cost: Optional[float]


class LLMClient:
    """
    A client for interacting with a specific, configured Large Language Model
    using LangChain's structured output capabilities.
    This class is instantiated with a configuration object.
    """
    chat_model: BaseChatModel
    model_name_for_cost: str # To store model name for cost estimation

    def __init__(self, llm_config: DB_LLMConfiguration):
        """
        Initializes the LLMClient with a specific configuration using LangChain models.
        """
        provider_name = llm_config.provider.lower()
        decrypted_api_key = getattr(llm_config, 'decrypted_api_key', None)
        if not decrypted_api_key:
            raise ValueError(f"API key for LLM config {llm_config.id} is missing or not decrypted.")

        self.model_name_for_cost = llm_config.model_name

        if provider_name == "openai":
            self.chat_model = ChatOpenAI(api_key=decrypted_api_key, model_name=llm_config.model_name)
        elif provider_name == "anthropic":
            self.chat_model = ChatAnthropic(api_key=decrypted_api_key, model_name=llm_config.model_name)
        elif provider_name == "google":
            # For Google, the parameter is 'model', not 'model_name' for ChatGoogleGenerativeAI
            self.chat_model = ChatGoogleGenerativeAI(google_api_key=decrypted_api_key, model=llm_config.model_name)
        else:
            raise ValueError(f"Unsupported LLM provider: {provider_name}")

        logger.info(f"LLMClient initialized with LangChain provider: {provider_name} for model {llm_config.model_name}")

    async def generate_structured_output(
        self, prompt: str, response_model: Type[T]
    ) -> "AgentLLMResult":
        """
        Generates structured output from the LLM, parsing it into the given Pydantic model.
        Uses LangChain's .with_structured_output() for robust parsing.
        """
        logger.debug(f"Generating structured output for model: {self.model_name_for_cost}, response_model: {response_model.__name__}")
        
        # Bind the Pydantic model to the chat model for structured output
        structured_llm = self.chat_model.with_structured_output(response_model)

        try:
            # The prompt passed here should be the direct instruction to the LLM.
            # LangChain's with_structured_output handles informing the LLM about the schema
            # and ensuring the output conforms to it.
            parsed_output = await structured_llm.ainvoke(prompt)
            
            # raw_output is not directly available from with_structured_output in a simple way.
            # Token counts for cost are also not directly available without callbacks.
            return AgentLLMResult(
                raw_output="[Structured output - raw text not directly available]",
                parsed_output=parsed_output,
                error=None,
                cost=cost_estimation.calculate_cost(
                    model_name=self.model_name_for_cost,
                    input_tokens=0, # Placeholder - token count not available here
                    output_tokens=0 # Placeholder - token count not available here
                ),
            )
        except Exception as e:
            logger.error(f"LLM generation or parsing with LangChain failed: {e}", exc_info=True)
            return AgentLLMResult(
                raw_output="[Structured output - error occurred]",
                parsed_output=None,
                error=str(e),
                cost=cost_estimation.calculate_cost(
                    model_name=self.model_name_for_cost,
                    input_tokens=0, # Placeholder
                    output_tokens=0  # Placeholder
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
