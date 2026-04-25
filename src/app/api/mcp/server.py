# src/app/api/mcp/server.py
"""FastMCP server exposing SCCAP's scanner + advisor surfaces as
Model Context Protocol tools, mounted at /mcp on the main FastAPI app.

Agentic clients (Claude Code, Cursor, etc.) authenticate with the
same JWT they'd use for the REST API: the `Authorization: Bearer
<token>` header is verified against the fastapi-users strategy via
`_SCCAPJWTVerifier`. Tool handlers resolve the authenticated user
out of the MCP request context so admin / ownership checks mirror
what `/api/v1/*` routes already enforce.

Tool surface (v1):
    - sccap_submit_scan
    - sccap_get_scan_status
    - sccap_get_scan_result
    - sccap_approve_scan
    - sccap_apply_fixes
    - sccap_ask_advisor
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.dependencies import get_access_token
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_users.db import SQLAlchemyUserDatabase

from app.config.config import settings
from app.core.services.chat_service import ChatService
from app.core.services.scan_service import SubmissionService
from app.infrastructure.auth.backend import get_custom_cookie_jwt_strategy
from app.infrastructure.auth.manager import UserManager
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import AsyncSessionLocal
from app.infrastructure.database.repositories.chat_repo import ChatRepository
from app.infrastructure.database.repositories.scan_repo import ScanRepository

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token verification — reuse fastapi-users' JWT strategy so MCP tokens and
# REST tokens are interchangeable.
# ---------------------------------------------------------------------------


class _SCCAPJWTVerifier(TokenVerifier):
    """Validates a SCCAP access token via fastapi-users' JWT strategy.

    Caches the user manager factory but resolves the user per-request so
    that deactivated accounts lose MCP access immediately.
    """

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        strategy = get_custom_cookie_jwt_strategy()
        try:
            async with AsyncSessionLocal() as session:
                user_db = SQLAlchemyUserDatabase(session, db_models.User)
                manager = UserManager(user_db)
                user = await strategy.read_token(token, manager)
        except Exception as e:  # pragma: no cover — auth errors are expected
            logger.debug("MCP token verify failed: %s", e)
            return None
        if user is None or not user.is_active:
            return None

        scopes = ["admin"] if user.is_superuser else ["user"]
        return AccessToken(
            token=token,
            client_id=str(user.id),
            scopes=scopes,
            expires_at=None,
            claims={
                "sub": str(user.id),
                "email": user.email,
                "is_superuser": user.is_superuser,
            },
        )


# ---------------------------------------------------------------------------
# Tool I/O schemas — Pydantic so FastMCP advertises a strict schema to
# callers and rejects malformed requests before our services run.
# ---------------------------------------------------------------------------


class SubmitScanFile(BaseModel):
    path: str = Field(description="Relative path to the file.")
    content: str = Field(description="Full file contents as a string.")


class SubmitScanInput(BaseModel):
    project_name: str
    scan_type: str = Field(
        description="AUDIT (find-only), SUGGEST (find + propose fixes), or REMEDIATE "
        "(find + apply fixes to a snapshot).",
        pattern="^(AUDIT|SUGGEST|REMEDIATE)$",
    )
    frameworks: List[str] = Field(
        description=(
            "Framework names the scan should apply. Must match names returned "
            "from the /compliance/stats endpoint (asvs, proactive_controls, "
            "cheatsheets, or custom ones)."
        )
    )
    utility_llm_config_id: str = Field(
        description="UUID of the LLM configuration used for scans."
    )
    files: Optional[List[SubmitScanFile]] = Field(
        default=None,
        description="Inline file contents. Mutually exclusive with repo_url.",
    )
    repo_url: Optional[str] = Field(
        default=None,
        description="Public git HTTPS URL. Mutually exclusive with files.",
    )


class AskAdvisorInput(BaseModel):
    question: str
    frameworks: Optional[List[str]] = Field(default=None)
    llm_config_id: Optional[str] = Field(
        default=None,
        description="Override the LLM config. Defaults to the first configured.",
    )


# ---------------------------------------------------------------------------
# Helpers for resolving the authenticated user inside tool handlers.
# ---------------------------------------------------------------------------


async def _current_user(session: AsyncSession) -> db_models.User:
    token = get_access_token()
    if token is None:
        raise PermissionError("No authenticated user available in MCP request context.")
    user_id = int(token.client_id)
    user = await session.get(db_models.User, user_id)
    if user is None or not user.is_active:
        raise PermissionError("Authenticated user not found or inactive.")
    return user


def _build_scan_service(repo: ScanRepository) -> SubmissionService:
    return SubmissionService(repo)


def _build_chat_service(session: AsyncSession) -> ChatService:
    return ChatService(chat_repo=ChatRepository(session))


# ---------------------------------------------------------------------------
# The FastMCP server. Tools are declared module-level so the singleton is
# easy to import from main.py.
# ---------------------------------------------------------------------------


mcp = FastMCP(
    name="SCCAP",
    auth=_SCCAPJWTVerifier(),
    instructions=(
        "Tools to drive SCCAP (Secure Coding & Compliance Automation Platform): "
        "submit scans, check status, fetch results, approve cost-estimated scans, "
        "apply AI-suggested fixes, and ask the security advisor one-shot questions. "
        "All tools require a SCCAP JWT bearer token."
    ),
)


@mcp.tool
async def sccap_submit_scan(payload: SubmitScanInput) -> Dict[str, Any]:
    """Submit a new scan.

    Provide either `files` (inline source) or `repo_url` (public git URL),
    not both. Returns `{scan_id, status}` — polling `sccap_get_scan_status`
    reveals when it hits `PENDING_COST_APPROVAL`, at which point call
    `sccap_approve_scan` to release the full analysis.
    """
    if bool(payload.files) == bool(payload.repo_url):
        raise ValueError("Provide exactly one of `files` or `repo_url`.")

    async with AsyncSessionLocal() as session:
        user = await _current_user(session)
        scan_service = _build_scan_service(ScanRepository(session))

        llm_cfg_id = uuid.UUID(payload.utility_llm_config_id)
        common_kwargs: Dict[str, Any] = dict(
            project_name=payload.project_name,
            user_id=user.id,
            scan_type=payload.scan_type,
            correlation_id=str(uuid.uuid4()),
            utility_llm_config_id=llm_cfg_id,
            fast_llm_config_id=llm_cfg_id,
            reasoning_llm_config_id=llm_cfg_id,
            frameworks=payload.frameworks,
        )

        if payload.files:
            # Bypass the FastAPI UploadFile shape by calling the private
            # launcher directly with pre-decoded file dicts.
            from app.shared.lib.files import get_language_from_filename

            files_data = [
                {
                    "path": f.path,
                    "content": f.content,
                    "language": get_language_from_filename(f.path) or "unknown",
                }
                for f in payload.files
            ]
            scan = await scan_service._process_and_launch_scan(
                files_data=files_data, **common_kwargs
            )
        else:
            assert payload.repo_url is not None
            scan = await scan_service.create_scan_from_git(
                repo_url=payload.repo_url, **common_kwargs
            )

    return {"scan_id": str(scan.id), "status": scan.status}


@mcp.tool
async def sccap_get_scan_status(scan_id: str) -> Dict[str, Any]:
    """Get the current status of a scan."""
    async with AsyncSessionLocal() as session:
        user = await _current_user(session)
        scan_service = _build_scan_service(ScanRepository(session))
        scan = await scan_service.get_scan_status(uuid.UUID(scan_id))
        if scan.user_id != user.id and not user.is_superuser:
            raise PermissionError("Not authorized to view this scan.")
        return {
            "scan_id": str(scan.id),
            "project_id": str(scan.project_id),
            "status": scan.status,
            "scan_type": scan.scan_type,
            "cost_details": scan.cost_details,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": (
                scan.completed_at.isoformat() if scan.completed_at else None
            ),
        }


@mcp.tool
async def sccap_get_scan_result(scan_id: str) -> Dict[str, Any]:
    """Fetch the final findings + summary for a completed scan. Returns
    an error dict if the scan is still running."""
    async with AsyncSessionLocal() as session:
        user = await _current_user(session)
        scan_service = _build_scan_service(ScanRepository(session))
        scan = await scan_service.get_scan_status(uuid.UUID(scan_id))
        if scan.user_id != user.id and not user.is_superuser:
            raise PermissionError("Not authorized to view this scan.")
        result = await scan_service.get_scan_result(uuid.UUID(scan_id))
        # get_scan_result returns a pydantic model; expose as plain dict.
        return (
            result.model_dump(mode="json") if hasattr(result, "model_dump") else result
        )


@mcp.tool
async def sccap_approve_scan(scan_id: str) -> Dict[str, Any]:
    """Approve a PENDING_COST_APPROVAL scan. Releases the full analysis
    via the Phase I.1 `interrupt() / Command(resume=...)` path."""
    async with AsyncSessionLocal() as session:
        user = await _current_user(session)
        scan_service = _build_scan_service(ScanRepository(session))
        await scan_service.approve_scan(uuid.UUID(scan_id), user=user)
        return {"scan_id": scan_id, "approved": True}


@mcp.tool
async def sccap_apply_fixes(
    scan_id: str, finding_ids: Optional[List[int]] = None
) -> Dict[str, Any]:
    """Apply AI-suggested fixes from a completed SUGGEST-mode scan. Pass
    `finding_ids` to apply a subset, or omit to apply all that have
    suggestions."""
    async with AsyncSessionLocal() as session:
        user = await _current_user(session)
        scan_service = _build_scan_service(ScanRepository(session))
        applied = await scan_service.apply_selective_fixes(
            uuid.UUID(scan_id), finding_ids=finding_ids, user=user
        )
        return {"scan_id": scan_id, "applied": applied}


@mcp.tool
async def sccap_ask_advisor(payload: AskAdvisorInput) -> Dict[str, Any]:
    """One-shot advisor query — skips session persistence. Returns the
    agent's answer + cost/tokens for tracking."""
    async with AsyncSessionLocal() as session:
        user = await _current_user(session)

        # Resolve LLM config: explicit override > user's most recent
        # chat session config > first available config.
        llm_config_id: Optional[uuid.UUID] = None
        if payload.llm_config_id:
            llm_config_id = uuid.UUID(payload.llm_config_id)
        else:
            chat_repo = ChatRepository(session)
            sessions = await chat_repo.get_sessions_for_user(user.id)
            if sessions and sessions[0].llm_config_id:
                llm_config_id = sessions[0].llm_config_id

        from app.infrastructure.agents.chat_agent import ChatAgent

        agent = ChatAgent()
        (content, _llm_interaction_id, cost) = await agent.generate_response(
            session_id=uuid.uuid4(),  # ephemeral — not persisted
            user_question=payload.question,
            history=[],
            llm_config_id=llm_config_id,
            frameworks=payload.frameworks or [],
        )

        # Keep user reference warm for the type-checker on sessions without
        # follow-up queries.
        _ = user
        _ = settings

        return {"answer": content, "cost_usd": cost}
