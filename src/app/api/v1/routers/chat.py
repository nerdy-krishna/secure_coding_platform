# src/app/api/v1/routers/chat.py
import logging
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.api.v1.dependencies import get_chat_service
import logging
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Response
from pydantic import BaseModel, Field

from app.api.v1.dependencies import get_chat_service
from app.core.services.chat_service import ChatService
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)
router = APIRouter()


# --- Pydantic Models for Chat API ---
class ChatSessionCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=100, description="The title for the new chat session.")
    project_id: Optional[uuid.UUID] = Field(None, description="Optional project ID to associate with the chat.")


class ChatSessionResponse(BaseModel):
    id: uuid.UUID
    title: str
    project_id: Optional[uuid.UUID]
    created_at: str

    class Config:
        from_attributes = True


class AskQuestionRequest(BaseModel):
    question: str = Field(..., min_length=1, description="The user's question.")
    llm_config_id: Optional[uuid.UUID] = Field(None, description="The specific LLM configuration to use for the response.")


class ChatMessageResponse(BaseModel):
    id: int
    role: str
    content: str
    timestamp: str

    class Config:
        from_attributes = True


# --- API Endpoints ---
@router.post("/sessions", response_model=ChatSessionResponse, status_code=status.HTTP_201_CREATED)
async def create_chat_session(
    request: ChatSessionCreateRequest,
    user: db_models.User = Depends(current_active_user),
    chat_service: ChatService = Depends(get_chat_service),
):
    """Starts a new chat session."""
    session = await chat_service.create_new_session(
        user=user, title=request.title, project_id=request.project_id
    )
    return ChatSessionResponse(
        id=session.id,
        title=session.title,
        project_id=session.project_id,
        created_at=session.created_at.isoformat(),
    )


@router.get("/sessions", response_model=List[ChatSessionResponse])
async def get_chat_sessions(
    user: db_models.User = Depends(current_active_user),
    chat_service: ChatService = Depends(get_chat_service),
):
    """Lists all of a user's past chat sessions."""
    sessions = await chat_service.get_user_sessions(user)
    return [
        ChatSessionResponse(
            id=s.id,
            title=s.title,
            project_id=s.project_id,
            created_at=s.created_at.isoformat(),
        )
        for s in sessions
    ]


@router.get("/sessions/{session_id}/messages", response_model=List[ChatMessageResponse])
async def get_session_messages(
    session_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    chat_service: ChatService = Depends(get_chat_service),
):
    """Gets all messages for a specific chat session."""
    messages = await chat_service.get_session_messages(session_id, user)
    return [
        ChatMessageResponse(
            id=m.id,
            role=m.role,
            content=m.content,
            timestamp=m.timestamp.isoformat(),
        )
        for m in messages
    ]


@router.post("/sessions/{session_id}/ask", response_model=ChatMessageResponse)
async def ask_question(
    session_id: uuid.UUID,
    request: AskQuestionRequest,
    user: db_models.User = Depends(current_active_user),
    chat_service: ChatService = Depends(get_chat_service),
):
    """Sends a message within a session and gets an AI-generated response."""
    ai_message = await chat_service.post_message_to_session(
        session_id=session_id,
        question=request.question,
        user=user,
        llm_config_id=request.llm_config_id,
    )
    return ChatMessageResponse(
        id=ai_message.id,
        role=ai_message.role,
        content=ai_message.content,
        timestamp=ai_message.timestamp.isoformat(),
    )


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_chat_session(
    session_id: uuid.UUID,
    user: db_models.User = Depends(current_active_user),
    chat_service: ChatService = Depends(get_chat_service),
):
    """Deletes a chat session and all its messages."""
    success = await chat_service.delete_session(session_id, user)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chat session not found or you do not have permission to delete it.",
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)