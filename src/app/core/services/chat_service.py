# src/app/core/services/chat_service.py
import logging
import uuid
from typing import List, Optional

from fastapi import HTTPException, status

from app.infrastructure.database.repositories.chat_repo import ChatRepository
from app.infrastructure.database import models as db_models
from app.api.v1 import models as api_models
from app.infrastructure.agents.chat_agent import ChatAgent

logger = logging.getLogger(__name__)


class ChatService:
    """Handles business logic for chat sessions and messages."""

    def __init__(self, chat_repo: ChatRepository):
        self.chat_repo = chat_repo
        # The ChatAgent will be instantiated on-demand
        self.chat_agent = ChatAgent()

    async def create_new_session(
        self, user: db_models.User, title: str, project_id: Optional[uuid.UUID] = None
    ) -> db_models.ChatSession:
        """Creates a new chat session for a user."""
        logger.info(
            f"User {user.id} creating new chat session with title '{title}'."
        )
        return await self.chat_repo.create_session(
            user_id=user.id, title=title, project_id=project_id
        )

    async def get_user_sessions(self, user: db_models.User) -> List[db_models.ChatSession]:
        """Retrieves all chat sessions for a user."""
        return await self.chat_repo.get_sessions_for_user(user.id)

    async def get_session_messages(
        self, session_id: uuid.UUID, user: db_models.User
    ) -> List[db_models.ChatMessage]:
        """Retrieves messages for a specific session, ensuring user has access."""
        messages = await self.chat_repo.get_messages_for_session(
            session_id=session_id, user_id=user.id
        )
        if not messages and not await self.chat_repo.get_session_by_id(session_id, user.id):
             raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Chat session not found or not authorized."
            )
        return messages


    async def post_message_to_session(
        self, session_id: uuid.UUID, question: str, user: db_models.User, llm_config_id: Optional[uuid.UUID]
    ) -> db_models.ChatMessage:
        """
        Posts a user's message, gets a response from the ChatAgent,
        and saves both messages to the database.
        """
        # 1. Verify user has access to the session
        session = await self.chat_repo.get_session_by_id(session_id, user.id)
        if not session:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Chat session not found or not authorized."
            )

        # 2. Save the user's message
        await self.chat_repo.add_message(
            session_id=session_id, role="user", content=question
        )

        # 3. Get conversation history for the agent
        history = await self.chat_repo.get_messages_for_session(session_id, user.id)

        # 4. Invoke the ChatAgent to get a response
        logger.info(f"Invoking ChatAgent for session {session_id}.")
        ai_response_content, llm_interaction_id = await self.chat_agent.generate_response(
            session_id=session_id,
            user_question=question,
            history=history,
            llm_config_id=llm_config_id
        )
        
        # 5. Save the AI's response
        ai_message = await self.chat_repo.add_message(
            session_id=session_id, role="assistant", content=ai_response_content
        )
        
        # 6. Link the LLM interaction to the AI's chat message
        if llm_interaction_id:
            await self.chat_repo.link_llm_interaction(ai_message.id, llm_interaction_id)

        return ai_message

    async def delete_session(self, session_id: uuid.UUID, user: db_models.User) -> bool:
        """Deletes a user's chat session."""
        logger.info(f"User {user.id} requesting to delete session {session_id}.")
        return await self.chat_repo.delete_session(session_id, user.id)