# src/app/infrastructure/database/repositories/chat_repo.py
import logging
import uuid
from typing import List, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


class ChatRepository:
    """Handles all database operations for Chat Sessions and Messages."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def create_session(
        self, user_id: int, title: str, project_id: Optional[uuid.UUID] = None
    ) -> db_models.ChatSession:
        """Creates a new chat session."""
        logger.info(
            f"Creating new chat session titled '{title}' for user {user_id}."
        )
        session = db_models.ChatSession(
            user_id=user_id, project_id=project_id, title=title
        )
        self.db.add(session)
        await self.db.commit()
        await self.db.refresh(session)
        return session

    async def get_session_by_id(
        self, session_id: uuid.UUID, user_id: int
    ) -> Optional[db_models.ChatSession]:
        """Retrieves a single chat session by its ID, ensuring user has access."""
        stmt = (
            select(db_models.ChatSession)
            .options(selectinload(db_models.ChatSession.messages))
            .filter_by(id=session_id, user_id=user_id)
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_sessions_for_user(self, user_id: int) -> List[db_models.ChatSession]:
        """Retrieves all chat sessions for a given user."""
        stmt = (
            select(db_models.ChatSession)
            .filter_by(user_id=user_id)
            .order_by(db_models.ChatSession.created_at.desc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def add_message(
        self, session_id: uuid.UUID, role: str, content: str
    ) -> db_models.ChatMessage:
        """Adds a new message to a chat session."""
        logger.debug(f"Adding '{role}' message to session {session_id}.")
        message = db_models.ChatMessage(session_id=session_id, role=role, content=content)
        self.db.add(message)
        await self.db.commit()
        await self.db.refresh(message)
        return message

    async def get_messages_for_session(
        self, session_id: uuid.UUID, user_id: int
    ) -> List[db_models.ChatMessage]:
        """
        Retrieves all messages for a session, verifying user ownership first.
        """
        session = await self.get_session_by_id(session_id, user_id)
        if not session:
            return []
        # The messages are already loaded via the relationship in get_session_by_id
        return sorted(session.messages, key=lambda m: m.timestamp)
    
    async def link_llm_interaction(self, chat_message_id: int, llm_interaction_id: int):
        """Links an LLMInteraction record to a ChatMessage."""
        stmt = (
            update(db_models.LLMInteraction)
            .where(db_models.LLMInteraction.id == llm_interaction_id)
            .values(chat_message_id=chat_message_id)
        )
        await self.db.execute(stmt)
        await self.db.commit()