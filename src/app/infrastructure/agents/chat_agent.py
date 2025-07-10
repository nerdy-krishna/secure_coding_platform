# src/app/infrastructure/agents/chat_agent.py
import logging
import uuid
from typing import List, Optional, Tuple

from pydantic import BaseModel, Field

from app.core.schemas import LLMInteraction
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.llm_config_repo import (
    LLMConfigRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database import AsyncSessionLocal as async_session_factory
from app.infrastructure.llm_client import get_llm_client, AgentLLMResult
from app.infrastructure.rag.rag_client import get_rag_service

logger = logging.getLogger(__name__)
AGENT_NAME = "SecurityAdvisorAgent"


class ChatResponse(BaseModel):
    """A simple Pydantic model for the chat response."""
    response: str = Field(description="The AI's response to the user's query.")


class ChatAgent:
    """
    An agent that provides security advice by querying a RAG service
    and using an LLM to generate responses.
    """

    async def _get_default_llm_config_id(self) -> Optional[uuid.UUID]:
        """Fetches the first available LLM configuration as a default."""
        async with async_session_factory() as db:
            llm_repo = LLMConfigRepository(db)
            configs = await llm_repo.get_all()
            if configs:
                return configs[0].id
        return None

    async def generate_response(
        self,
        session_id: uuid.UUID,
        user_question: str,
        history: List[db_models.ChatMessage],
        llm_config_id: Optional[uuid.UUID],
    ) -> Tuple[str, Optional[int]]:
        """
        Generates a context-aware response to a user's question.

        Returns:
            A tuple containing the string response and the ID of the LLMInteraction record.
        """
        logger.info(f"[{AGENT_NAME}] Generating response for session {session_id}.")

        # 1. Get RAG context
        rag_service = get_rag_service()
        if not rag_service:
            logger.error(f"[{AGENT_NAME}] Could not get RAG service for session {session_id}.")
            return "Error: Could not connect to the knowledge base.", None
        
        try:
            retrieved_docs = rag_service.query_asvs(query_texts=[user_question], n_results=5)
            docs = retrieved_docs.get("documents")
            rag_context = "\n".join(docs[0]) if docs and docs[0] else "No specific security context found."
        except Exception as e:
            logger.error(f"[{AGENT_NAME}] Failed to query RAG service: {e}", exc_info=True)
            rag_context = "Warning: Could not retrieve information from the security knowledge base."

        # 2. Get LLM Client
        if not llm_config_id:
            llm_config_id = await self._get_default_llm_config_id()
        
        if not llm_config_id:
            logger.error(f"[{AGENT_NAME}] No LLM configuration available.")
            return "Error: The AI language model is not configured. Please contact an administrator.", None
            
        llm_client = await get_llm_client(llm_config_id)
        if not llm_client:
            logger.error(f"[{AGENT_NAME}] Failed to initialize LLM client for config {llm_config_id}.")
            return "Error: Could not initialize the AI language model.", None

        # 3. Build the prompt
        history_str = "\n".join([f"{msg.role}: {msg.content}" for msg in history])
        prompt = f"""
        You are an expert AI Security Advisor. Your role is to provide clear, accurate, and helpful advice on software security.
        Use the provided conversation history and security context to answer the user's question.
        If the context is not relevant, rely on your general security knowledge. Be concise and helpful.

        <CONVERSATION_HISTORY>
        {history_str}
        </CONVERSATION_HISTORY>

        <SECURITY_CONTEXT_FROM_KNOWLEDGE_BASE>
        {rag_context}
        </SECURITY_CONTEXT_FROM_KNOWLEDGE_BASE>

        Current User Question: "{user_question}"

        Provide your response as a single, helpful answer.
        """

        # 4. Generate response
        llm_response: AgentLLMResult = await llm_client.generate_structured_output(
            prompt, ChatResponse
        )
        
        ai_response_content = "I am having trouble processing this request. Please try again."
        if llm_response.parsed_output:
            ai_response_content = llm_response.parsed_output.response
        elif llm_response.error:
            logger.error(f"[{AGENT_NAME}] LLM error for session {session_id}: {llm_response.error}")
        
        # 5. Create and save LLMInteraction record
        llm_interaction_record = None
        async with async_session_factory() as db:
            repo = ScanRepository(db)
            interaction = LLMInteraction(
                agent_name=AGENT_NAME,
                prompt_template_name="SecurityAdvisorPrompt",
                prompt_context={"question": user_question, "history_length": len(history), "rag_context": rag_context},
                raw_response=llm_response.raw_output,
                parsed_output=llm_response.parsed_output.model_dump() if llm_response.parsed_output else None,
                error=llm_response.error,
                cost=llm_response.cost,
                input_tokens=llm_response.prompt_tokens,
                output_tokens=llm_response.completion_tokens,
                total_tokens=llm_response.total_tokens,
            )
            # This needs to be done via the repo to get the ID back
            db_interaction = db_models.LLMInteraction(**interaction.model_dump())
            db.add(db_interaction)
            await db.commit()
            await db.refresh(db_interaction)
            llm_interaction_record_id = db_interaction.id

        return ai_response_content, llm_interaction_record_id