# src/app/db/crud.py

import logging
import uuid
from typing import List, Dict, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

# Correctly import all models from a single source of truth
from app.db import models as db_models
from app.auth.models import User
from app.api import models as api_models
from app.agents import schemas as agent_schemas
from app.utils.encryption import FernetEncrypt

logger = logging.getLogger(__name__)

# === LLMConfiguration CRUD Functions (NEW) ===


async def get_llm_config(
    db: AsyncSession, config_id: uuid.UUID
) -> Optional[db_models.LLMConfiguration]:
    """Retrieves a single LLM configuration by its ID."""
    result = await db.execute(
        select(db_models.LLMConfiguration).filter(
            db_models.LLMConfiguration.id == config_id
        )
    )
    return result.scalars().first()


async def get_llm_config_with_decrypted_key(
    db: AsyncSession, config_id: uuid.UUID
) -> Optional[db_models.LLMConfiguration]:
    """Retrieves an LLM config and adds a temporary 'decrypted_api_key' attribute."""
    config = await get_llm_config(db, config_id)
    if config:
        setattr(
            config, "decrypted_api_key", FernetEncrypt.decrypt(config.encrypted_api_key)
        )
    return config


async def get_llm_configs(
    db: AsyncSession, skip: int = 0, limit: int = 100
) -> List[db_models.LLMConfiguration]:
    """Retrieves a list of all LLM configurations."""
    result = await db.execute(
        select(db_models.LLMConfiguration)
        .order_by(db_models.LLMConfiguration.name)
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


async def create_llm_config(
    db: AsyncSession, config: api_models.LLMConfigurationCreate
) -> db_models.LLMConfiguration:
    """Creates a new LLM configuration, encrypting the API key before storage."""
    encrypted_key = FernetEncrypt.encrypt(config.api_key)
    db_config = db_models.LLMConfiguration(
        name=config.name,
        provider=config.provider,
        model_name=config.model_name,
        encrypted_api_key=encrypted_key,
    )
    db.add(db_config)
    await db.commit()
    await db.refresh(db_config)
    return db_config


async def delete_llm_config(
    db: AsyncSession, config_id: uuid.UUID
) -> Optional[db_models.LLMConfiguration]:
    """Deletes an LLM configuration by its ID."""
    config = await get_llm_config(db, config_id)
    if config:
        await db.delete(config)
        await db.commit()
    return config


# === User CRUD (Corrected) ===


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    """Retrieves a user by their email address."""
    result = await db.execute(select(User).filter(User.email == email))
    return result.scalars().first()


# === Submission & Analysis CRUD (Rewritten & Corrected) ===


async def create_submission(
    db: AsyncSession,
    user_id: uuid.UUID,
    repo_url: Optional[str] = None,
    files: Optional[List[Dict]] = None,
    frameworks: Optional[List[str]] = None,
    main_llm_config_id: Optional[uuid.UUID] = None,
    specialized_llm_config_id: Optional[uuid.UUID] = None,
) -> db_models.CodeSubmission:
    """Creates a new code submission record."""
    submission = db_models.CodeSubmission(
        user_id=user_id,
        repo_url=repo_url,
        status="Pending",
        frameworks=frameworks,
        main_llm_config_id=main_llm_config_id,
        specialized_llm_config_id=specialized_llm_config_id,
    )
    db.add(submission)
    await db.commit()
    await db.refresh(submission)

    if files:
        await add_files_to_submission(db, submission.id, files)

    return submission


async def add_files_to_submission(
    db: AsyncSession, submission_id: uuid.UUID, files: List[Dict[str, str]]
):
    """Adds multiple files to an existing submission."""
    db_files = [
        db_models.SubmittedFile(
            submission_id=submission_id,
            file_path=file["path"],
            content=file["content"],
            language=file.get("language", "unknown"),
        )
        for file in files
    ]
    db.add_all(db_files)
    await db.commit()


async def get_submission(
    db: AsyncSession, submission_id: uuid.UUID
) -> Optional[db_models.CodeSubmission]:
    """Retrieves a submission by ID, with related files and findings."""
    result = await db.execute(
        select(db_models.CodeSubmission)
        .options(
            selectinload(db_models.CodeSubmission.files),
            selectinload(db_models.CodeSubmission.findings).selectinload(
                db_models.VulnerabilityFinding.fixes
            ),
        )
        .filter(db_models.CodeSubmission.id == submission_id)
    )
    return result.scalars().first()


async def update_submission_status(
    db: AsyncSession, submission_id: uuid.UUID, status: str
):
    """Updates the status of a submission."""
    stmt = (
        update(db_models.CodeSubmission)
        .where(db_models.CodeSubmission.id == submission_id)
        .values(status=status)
    )
    await db.execute(stmt)
    await db.commit()


async def save_llm_interaction(
    db: AsyncSession, interaction_data: agent_schemas.LLMInteraction
):
    """Saves a record of an interaction with an LLM."""
    # This now correctly uses the pydantic model directly
    db_interaction = db_models.LLMInteraction(**interaction_data.model_dump())
    db.add(db_interaction)
    await db.commit()


async def save_findings(
    db: AsyncSession,
    submission_id: uuid.UUID,
    findings: List[agent_schemas.VulnerabilityFinding],
) -> List[db_models.VulnerabilityFinding]:
    """Saves a list of vulnerability findings and returns the persisted objects."""
    if not findings:
        return []

    db_findings = [
        db_models.VulnerabilityFinding(
            submission_id=submission_id,
            file_path=finding.file_path,
            cwe=finding.cwe,
            description=finding.description,
            severity=finding.severity,
            line_number=finding.line_number,
            remediation=finding.remediation,
            confidence=finding.confidence,
            references=finding.references,
        )
        for finding in findings
    ]
    db.add_all(db_findings)
    await db.flush()  # Use flush to get IDs before commit
    for finding in db_findings:
        await db.refresh(finding)
    await db.commit()
    return db_findings


async def save_fix_suggestion(
    db: AsyncSession, finding_id: int, suggestion: agent_schemas.FixSuggestion
):
    """Saves a code fix suggestion for a specific vulnerability finding."""
    fix = db_models.FixSuggestion(
        finding_id=finding_id,
        description=suggestion.description,
        suggested_fix=suggestion.code,
    )
    db.add(fix)
    await db.commit()
