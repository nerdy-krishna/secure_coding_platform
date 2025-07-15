# src/app/infrastructure/agents/symbol_map_agent.py
import logging
import uuid
from typing import List, Dict, Optional

from pydantic import BaseModel, Field

from app.infrastructure.llm_client import get_llm_client
from app.core.schemas import CodeChunk

logger = logging.getLogger(__name__)

class SymbolSummary(BaseModel):
    symbol_name: str = Field(description="The exact name of the function or class.")
    summary: str = Field(description="A concise, one-sentence description of the symbol's purpose.")

class SymbolMapResponse(BaseModel):
    """The expected structured response from the LLM for generating a symbol map."""
    symbols: List[SymbolSummary]

async def generate_symbol_map(
    llm_config_id: uuid.UUID,
    chunks: List[CodeChunk],
    file_path: str,
) -> Optional[Dict[str, str]]:
    """
    Uses an LLM to generate a map of symbol names to their one-sentence descriptions.
    """
    llm_client = await get_llm_client(llm_config_id)
    if not llm_client:
        logger.error(f"Failed to get LLM client for symbol map generation for {file_path}.")
        return None

    # Format the code snippets for the prompt
    code_snippets_str = ""
    for chunk in chunks:
        code_snippets_str += f"--- Symbol: {chunk['symbol_name']} ---\n"
        code_snippets_str += f"{chunk['code']}\n\n"

    prompt = f"""
    Based on the following code snippets from the file '{file_path}', generate a concise, one-sentence summary for each symbol (function or class) describing its primary purpose.

    CODE SNIPPETS:
    {code_snippets_str}

    Respond ONLY with a valid JSON object that strictly adheres to the provided SymbolMapResponse schema. Each symbol from the input must have a corresponding summary.
    """

    try:
        response = await llm_client.generate_structured_output(prompt, SymbolMapResponse)
        if response.error or not response.parsed_output or not isinstance(response.parsed_output, SymbolMapResponse):
            logger.error(f"LLM failed to generate symbol map for {file_path}: {response.error or 'Invalid output schema'}")
            return None
        
        symbol_map = {item.symbol_name: item.summary for item in response.parsed_output.symbols}
        logger.info(f"Successfully generated symbol map for {file_path}.")
        return symbol_map
    except Exception as e:
        logger.error(f"Exception during symbol map generation for {file_path}: {e}", exc_info=True)
        return None