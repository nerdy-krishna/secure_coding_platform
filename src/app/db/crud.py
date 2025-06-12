# src/app/db/crud.py
import logging
from typing import List, Dict, Any, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.app.db.models import (
    CodeSubmission,
    SubmittedFile,
    LLMInteraction,
    VulnerabilityFinding,
    FixSuggestion,
)
from src.app.auth.models import User

# Corrected import to point to the new schemas file, breaking the circular dependency
from src.app.agents.schemas import (
    VulnerabilityFinding as VulnerabilityFindingModel,
    FixSuggestion as FixSuggestionModel,
)

logger = logging.getLogger(__name__)

# ... (the rest of the file remains exactly the same) ...

async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    """Retrieves a user by their email address."""
    result = await db.execute(select(User).filter(User.email == email))
    return result.scalars().first()


async def create_submission(
    db: AsyncSession, user_id: int, repo_url: Optional[str] = None
) -> CodeSubmission:
    """Creates a new code submission record."""
    submission = CodeSubmission(user_id=user_id, repo_url=repo_url, status="Pending")
    db.add(submission)
    await db.commit()
    await db.refresh(submission)
    return submission


async def add_files_to_submission(
    db: AsyncSession, submission_id: int, files: List[Dict[str, str]]
):
    """Adds multiple files to an existing submission."""
    db_files = [
        SubmittedFile(
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
    db: AsyncSession, submission_id: int
) -> Optional[CodeSubmission]:
    """Retrieves a submission by its ID, including related files and findings."""
    result = await db.execute(
        select(CodeSubmission)
        .options(
            selectinload(CodeSubmission.files),
            selectinload(CodeSubmission.findings).selectinload(VulnerabilityFinding.fixes),
        )
        .filter(CodeSubmission.id == submission_id)
    )
    return result.scalars().first()


async def get_submission_files(
    db: AsyncSession, submission_id: int
) -> List[SubmittedFile]:
    """Retrieves all files associated with a submission."""
    result = await db.execute(
        select(SubmittedFile).filter(SubmittedFile.submission_id == submission_id)
    )
    return result.scalars().all()


async def update_submission_status(db: AsyncSession, submission_id: int, status: str):
    """Updates the status of a submission."""
    await db.execute(
        update(CodeSubmission).where(CodeSubmission.id == submission_id).values(status=status)
    )
    await db.commit()


async def update_submission_file_context(
    db: AsyncSession,
    submission_id: int,
    file_path: str,
    analysis_summary: Optional[str],
    identified_components: Optional[List[str]],
    asvs_analysis: Optional[Dict[str, Any]],
):
    """Updates a submission file with context analysis results."""
    await db.execute(
        update(SubmittedFile)
        .where(
            SubmittedFile.submission_id == submission_id,
            SubmittedFile.file_path == file_path,
        )
        .values(
            analysis_summary=analysis_summary,
            identified_components=identified_components,
            asvs_analysis=asvs_analysis,
        )
    )
    await db.commit()


async def save_llm_interaction(
    db: AsyncSession,
    submission_id: int,
    agent_name: str,
    prompt: str,
    raw_response: str,
    parsed_output: Optional[Dict],
    error: Optional[str] = None,
    file_path: Optional[str] = None,
    cost: Optional[float] = None,
):
    """Saves a record of an interaction with the LLM."""
    interaction = LLMInteraction(
        submission_id=submission_id,
        file_path=file_path,
        agent_name=agent_name,
        prompt=prompt,
        raw_response=raw_response,
        parsed_output=parsed_output,
        error=error,
        cost=cost,
    )
    db.add(interaction)
    await db.commit()


async def save_findings(
    db: AsyncSession, submission_id: int, findings: List[VulnerabilityFindingModel]
) -> List[VulnerabilityFinding]:
    """Saves a list of vulnerability findings and returns the persisted objects with their IDs."""
    if not findings:
        return []

    db_findings = [
        VulnerabilityFinding(
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
    await db.flush()
    for finding in db_findings:
        await db.refresh(finding)
    await db.commit()
    logger.info(
        f"Successfully saved {len(db_findings)} findings for submission {submission_id}."
    )
    return db_findings


async def save_fix_suggestion(
    db: AsyncSession, finding_id: int, suggestion: FixSuggestionModel
):
    """Saves a code fix suggestion for a specific vulnerability finding."""
    fix = FixSuggestion(
        finding_id=finding_id,
        description=suggestion.description,
        suggested_fix=suggestion.code,
    )
    db.add(fix)
    await db.commit()


async def get_findings_for_submission(
    db: AsyncSession, submission_id: int
) -> List[VulnerabilityFinding]:
    """Retrieves all vulnerability findings for a given submission, for API/frontend use."""
    result = await db.execute(
        select(VulnerabilityFinding)
        .filter(VulnerabilityFinding.submission_id == submission_id)
        .order_by(VulnerabilityFinding.file_path, VulnerabilityFinding.line_number)
    )
    return result.scalars().all()


async def get_fixes_for_finding(
    db: AsyncSession, finding_id: int
) -> List[FixSuggestion]:
    """Retrieves all fix suggestions for a given finding, for API/frontend use."""
    result = await db.execute(
        select(FixSuggestion).filter(FixSuggestion.finding_id == finding_id)
    )
    return result.scalars().all()