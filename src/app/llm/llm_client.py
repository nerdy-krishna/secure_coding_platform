# src/app/llm/llm_client.py
# src/app/llm/llm_client.py                                                                                                                                                                                        
import logging                                                                                                                                                                                                     
import json                                                                                                                                                                                                        
import uuid                                                                                                                                                                                                        
import re # Added import for regular expressions                                                                                                                                                                   
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
                                                                                                                                                                                                                   
    def _extract_json_from_text(self, text: str) -> Optional[Dict[str, Any]]:                                                                                                                                      
        """                                                                                                                                                                                                        
        Extracts a JSON object from a string.                                                                                                                                                                      
        It first looks for a ```json ... ``` markdown block.                                                                                                                                                       
        If not found or if parsing that fails, it falls back to finding the first '{' and last '}'.                                                                                                                
        """                                                                                                                                                                                                        
        # Try to extract from ```json ... ``` code block                                                                                                                                                           
        # This regex handles optional whitespace and newlines around the JSON content                                                                                                                              
        match = re.search(r"```json\s*(\{[\s\S]*?\})\s*```", text, re.DOTALL)                                                                                                                                      
        if match:                                                                                                                                                                                                  
            json_str = match.group(1)                                                                                                                                                                              
            json_str_fixed = "" # Initialize to prevent reference before assignment in logger                                                                                                                      
            try:                                                                                                                                                                                                   
                # Attempt to fix common escape issues before parsing                                                                                                                                               
                # Replace single backslashes (not already part of a valid escape like \n, \t, \\, \", etc.)                                                                                                        
                # with double backslashes. This is a common issue with LLM-generated JSON.                                                                                                                         
                # This regex looks for a backslash not followed by common valid escape characters or another backslash.                                                                                            
                # It's a heuristic and might need refinement if other escape issues appear.                                                                                                                        
                #                                                                                                                                                                                                  
                # Known valid JSON escapes: \b, \f, \n, \r, \t, \", \\, \/ (and \uXXXX for unicode)                                                                                                                
                # This regex tries to replace a backslash if it's NOT followed by one of these or 'u'                                                                                                              
                json_str_fixed = re.sub(r'\\(?![bfnrt"\\/u])', r'\\\\', json_str)                                                                                                                                  
                                                                                                                                                                                                                   
                return json.loads(json_str_fixed)                                                                                                                                                                  
            except json.JSONDecodeError as e:                                                                                                                                                                      
                logger.error(                                                                                                                                                                                      
                    f"Failed to parse JSON from ```json``` block: {e}. Original content: '{json_str[:200]}...'. Fixed content: '{json_str_fixed[:200]}...'"                                                        
                )                                                                                                                                                                                                  
                # If the explicit block is found but malformed, we might not want to fall back,                                                                                                                    
                # as it indicates the LLM tried but failed to follow the format.                                                                                                                                   
                # However, for robustness, we can still try the fallback.                                                                                                                                          
                # For now, let's return None to indicate this specific extraction failed.                                                                                                                          
                # If issues persist, consider removing the fallback or making it more conditional.                                                                                                                 
                # return None # Option 1: Strict: if ```json is there, it must be valid.                                                                                                                           
                                                                                                                                                                                                                   
        # Fallback or if ```json block not found: Look for the first '{' to start, and the last '}' to end                                                                                                         
        # This is less reliable.                                                                                                                                                                                   
        if not match: # Only try fallback if ```json block was not found                                                                                                                                           
            logger.warning(                                                                                                                                                                                        
                "Could not find ```json ... ``` block, attempting fallback {...} extraction."                                                                                                                      
            )                                                                                                                                                                                                      
                                                                                                                                                                                                                   
        json_str_fallback = "" # Initialize for logger in except block                                                                                                                                             
        json_str_fallback_fixed = "" # Initialize for logger in except block                                                                                                                                       
        try:                                                                                                                                                                                                       
            json_start = text.find("{")                                                                                                                                                                            
            json_end = text.rfind("}")                                                                                                                                                                             
            if json_start != -1 and json_end != -1 and json_end > json_start:                                                                                                                                      
                json_str_fallback = text[json_start : json_end + 1]                                                                                                                                                
                # Apply the same fix for fallback                                                                                                                                                                  
                json_str_fallback_fixed = re.sub(r'\\(?![bfnrt"\\/u])', r'\\\\', json_str_fallback)                                                                                                                
                return json.loads(json_str_fallback_fixed)                                                                                                                                                         
            else:                                                                                                                                                                                                  
                # This log will now only appear if neither ```json nor {...} is found.                                                                                                                             
                logger.error(                                                                                                                                                                                      
                    f"No JSON-like structure (neither ```json``` nor {{...}}) found in text. Text (first 500 chars): {text[:500]}"                                                                                 
                )                                                                                                                                                                                                  
                return None                                                                                                                                                                                        
        except json.JSONDecodeError as e:                                                                                                                                                                          
            # This error now specifically relates to the fallback or if the primary regex failed and we retried.                                                                                                   
            logger.error(                                                                                                                                                                                          
                f"Failed to parse JSON using fallback or after primary extraction: {e}. Original fallback content: '{json_str_fallback[:500]}...'. Fixed content: '{json_str_fallback_fixed[:500]}...'"            
            )                                                                                                                                                                                                      
            return None                                                                                                                                                                                            
        except Exception as e: # Catch any other unexpected errors during string manipulation                                                                                                                      
            logger.error(f"Unexpected error during JSON extraction: {e}. Text (first 500 chars): '{text[:500]}...'" )                                                                                              
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
