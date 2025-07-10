# src/app/infrastructure/database/repositories/chat_repo.py
import logging
import uuid
from typing import List, Optional

from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)


class ChatRepository:
    """Handles all database operations for Chat Sessions and Messages."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def create_session(
        self,
        user_id: int,
        title: str,
        llm_config_id: uuid.UUID,
        frameworks: List[str],
        project_id: Optional[uuid.UUID] = None,
    ) -> db_models.ChatSession:
        """Creates a new chat session."""
        logger.info(
            f"Creating new chat session titled '{title}' for user {user_id}."
        )
        session = db_models.ChatSession(
            user_id=user_id,
            project_id=project_id,
            title=title,
            llm_config_id=llm_config_id,
            frameworks=frameworks,
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
        self, session_id: uuid.UUID, role: str, content: str, cost: Optional[float] = None
    ) -> db_models.ChatMessage:
        """Adds a new message to a chat session."""
        logger.debug(f"Adding '{role}' message to session {session_id}.")
        message = db_models.ChatMessage(
            session_id=session_id, role=role, content=content, cost=cost
        )
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

    async def replace_messages_with_summary(
        self,
        session_id: uuid.UUID,
        message_ids_to_delete: List[int],
        summary_content: str,
    ):
        """
        Atomically deletes a list of messages and inserts a new system message
        with the summary of the deleted content.
        """
        logger.info(f"Summarizing {len(message_ids_to_delete)} messages for session {session_id}.")
        # First, nullify any LLM interaction foreign keys to avoid constraint violations
        stmt_nullify_fk = (
            update(db_models.LLMInteraction)
            .where(db_models.LLMInteraction.chat_message_id.in_(message_ids_to_delete))
            .values(chat_message_id=None)
        )
        await self.db.execute(stmt_nullify_fk)

        # Delete the old messages
        stmt_delete = delete(db_models.ChatMessage).where(
            db_models.ChatMessage.id.in_(message_ids_to_delete)
        )
        await self.db.execute(stmt_delete)

        # Add the new summary message
        summary_message = db_models.ChatMessage(
            session_id=session_id,
            role="system",
            content=f"Summary of earlier conversation: {summary_content}",
        )
        self.db.add(summary_message)
        await self.db.commit()
        logger.info(f"Successfully replaced old messages with summary for session {session_id}.")


    async def delete_session(self, session_id: uuid.UUID, user_id: int) -> bool:
        """Deletes a chat session and all its messages, ensuring user owns it."""
        logger.info(f"Attempting to delete chat session {session_id} for user {user_id}.")
        # First, get the session with its messages and their LLM interactions
        stmt = (
            select(db_models.ChatSession)
            .options(
                selectinload(db_models.ChatSession.messages)
                .selectinload(db_models.ChatMessage.llm_interaction)
            )
            .filter_by(id=session_id, user_id=user_id)
        )
        result = await self.db.execute(stmt)
        session = result.scalars().first()

        if not session:
            logger.warning(f"Delete failed: Session {session_id} not found for user {user_id}.")
            return False

        # The relationships are configured with cascade="all, delete-orphan",
        # so deleting the session will automatically delete its messages.
        # However, the link from LLMInteraction is nullable, so we need to handle that.
        # We will just nullify the back-reference. The LLM interaction log itself is preserved.
        for message in session.messages:
            if message.llm_interaction:
                message.llm_interaction.chat_message_id = None

        await self.db.delete(session)
        await self.db.commit()
        logger.info(f"Successfully deleted chat session {session_id}.")
        return True

    async def link_llm_interaction(self, chat_message_id: int, llm_interaction_id: int):
        """Links an LLMInteraction record to a ChatMessage."""
        stmt = (
            update(db_models.LLMInteraction)
            .where(db_models.LLMInteraction.id == llm_interaction_id)
            .values(chat_message_id=chat_message_id)
        )
        await self.db.execute(stmt)
        await self.db.commit()