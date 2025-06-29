# src/app/infrastructure/database/repositories/submission_repo.py

import logging
import uuid
import datetime
from typing import List, Dict, Optional, Any

from sqlalchemy import String, cast, func, select, update, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, aliased

from app.infrastructure.database import models as db_models
from app.core import schemas as agent_schemas

logger = logging.getLogger(__name__)


class SubmissionRepository:
    """
    Handles all database operations related to submissions, files, findings,
    reports, and their associated data.
    """

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def create_submission(
        self,
        user_id: int,
        project_name: str,
        repo_url: Optional[str],
        files: List[Dict[str, Any]],
        frameworks: List[str],
        excluded_files: List[str],
        main_llm_id: uuid.UUID,
        specialized_llm_id: uuid.UUID,
    ) -> db_models.CodeSubmission:
        submission = db_models.CodeSubmission(
            user_id=user_id,
            project_name=project_name,
            repo_url=repo_url,
            status="Pending",
            frameworks=frameworks,
            excluded_files=excluded_files,
            main_llm_config_id=main_llm_id,
            specialized_llm_config_id=specialized_llm_id,
        )
        self.db.add(submission)
        await self.db.flush()
        db_files = [
            db_models.SubmittedFile(submission_id=submission.id, **f) for f in files
        ]
        self.db.add_all(db_files)
        await self.db.commit()
        await self.db.refresh(submission)
        return submission

    async def get_submission(
        self, submission_id: uuid.UUID
    ) -> Optional[db_models.CodeSubmission]:
        result = await self.db.execute(
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

    async def get_submitted_files_for_submission(
        self, submission_id: uuid.UUID
    ) -> List[db_models.SubmittedFile]:
        result = await self.db.execute(
            select(db_models.SubmittedFile).filter(
                db_models.SubmittedFile.submission_id == submission_id
            )
        )
        return list(result.scalars().all())

    async def update_status(self, submission_id: uuid.UUID, status: str):
        stmt = (
            update(db_models.CodeSubmission)
            .where(db_models.CodeSubmission.id == submission_id)
            .values(status=status)
        )
        await self.db.execute(stmt)
        await self.db.commit()

    async def save_llm_interaction(
        self, interaction_data: agent_schemas.LLMInteraction
    ):
        db_interaction = db_models.LLMInteraction(**interaction_data.model_dump())
        self.db.add(db_interaction)
        await self.db.commit()

    async def save_findings(
        self,
        submission_id: uuid.UUID,
        findings: List[agent_schemas.VulnerabilityFinding],
    ) -> List[db_models.VulnerabilityFinding]:
        if not findings:
            return []
        db_findings = [
            db_models.VulnerabilityFinding(
                submission_id=submission_id, **finding.model_dump()
            )
            for finding in findings
        ]
        self.db.add_all(db_findings)
        await self.db.flush()
        for finding in db_findings:
            await self.db.refresh(finding)
        await self.db.commit()
        return db_findings

    async def save_fix_suggestion(
        self, finding_id: int, suggestion: agent_schemas.FixSuggestion
    ):
        fix = db_models.FixSuggestion(
            finding_id=finding_id,
            description=suggestion.description,
            suggested_fix=suggestion.code,
        )
        self.db.add(fix)
        await self.db.commit()

    async def update_cost_and_status(
        self, submission_id: uuid.UUID, status: str, estimated_cost: Dict[str, Any]
    ):
        stmt = (
            update(db_models.CodeSubmission)
            .where(db_models.CodeSubmission.id == submission_id)
            .values(status=status, estimated_cost=estimated_cost)
        )
        await self.db.execute(stmt)
        await self.db.commit()

    async def save_final_reports_and_status(
        self,
        submission_id: uuid.UUID,
        status: str,
        impact_report: Optional[Dict[str, Any]],
        sarif_report: Optional[Dict[str, Any]],
        risk_score: Optional[int],
    ):
        completed_at_aware = datetime.datetime.now(datetime.timezone.utc)
        values = {
            "status": status,
            "completed_at": completed_at_aware,
            "risk_score": risk_score,
        }
        if impact_report:
            values["impact_report"] = impact_report
        if sarif_report:
            values["sarif_report"] = sarif_report
        stmt = (
            update(db_models.CodeSubmission)
            .where(db_models.CodeSubmission.id == submission_id)
            .values(**values)
        )
        await self.db.execute(stmt)
        await self.db.commit()

    async def update_remediated_code_and_status(
        self, submission_id: uuid.UUID, status: str, fixed_code_map: Dict[str, Any]
    ):
        completed_at_aware = datetime.datetime.now(datetime.timezone.utc)
        values = {
            "status": status,
            "completed_at": completed_at_aware,
            "fixed_code_map": fixed_code_map,
        }
        stmt = (
            update(db_models.CodeSubmission)
            .where(db_models.CodeSubmission.id == submission_id)
            .values(**values)
        )
        await self.db.execute(stmt)
        await self.db.commit()

    async def get_paginated_history(
        self, user_id: int, skip: int, limit: int, search: Optional[str]
    ) -> List[Dict[str, Any]]:
        llm_interaction_alias = aliased(db_models.LLMInteraction)
        cost_subquery = (
            select(
                llm_interaction_alias.submission_id,
                func.sum(llm_interaction_alias.cost).label("total_cost"),
                func.sum(llm_interaction_alias.input_tokens).label(
                    "total_input_tokens"
                ),
                func.sum(llm_interaction_alias.output_tokens).label(
                    "total_output_tokens"
                ),
                func.sum(llm_interaction_alias.total_tokens).label("total_tokens"),
            )
            .group_by(llm_interaction_alias.submission_id)
            .subquery()
        )
        stmt = (
            select(
                db_models.CodeSubmission,
                cost_subquery.c.total_cost,
                cost_subquery.c.total_input_tokens,
                cost_subquery.c.total_output_tokens,
                cost_subquery.c.total_tokens,
            )
            .outerjoin(
                cost_subquery,
                db_models.CodeSubmission.id == cost_subquery.c.submission_id,
            )
            .filter(db_models.CodeSubmission.user_id == user_id)
        )

        if search:
            stmt = stmt.filter(
                or_(
                    db_models.CodeSubmission.project_name.ilike(f"%{search}%"),
                    cast(db_models.CodeSubmission.id, String).ilike(f"%{search}%"),
                )
            )

        stmt = (
            stmt.order_by(db_models.CodeSubmission.submitted_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await self.db.execute(stmt)

        results_with_cost = []
        for row in result.all():
            submission, total_cost, total_input, total_output, total_tokens = row
            results_with_cost.append(
                {
                    "id": submission.id,
                    "project_name": submission.project_name,
                    "status": submission.status,
                    "submitted_at": submission.submitted_at,
                    "completed_at": submission.completed_at,
                    "estimated_cost": submission.estimated_cost,
                    "actual_cost": {
                        "total_cost": total_cost or 0.0,
                        "total_input_tokens": total_input or 0,
                        "total_output_tokens": total_output or 0,
                        "total_tokens": total_tokens or 0,
                    }
                    if submission.status in ["Completed", "Remediation-Completed"]
                    else None,
                }
            )
        return results_with_cost

    async def get_history_count(
        self, user_id: int, search: Optional[str] = None
    ) -> int:
        stmt = select(func.count(db_models.CodeSubmission.id)).filter(
            db_models.CodeSubmission.user_id == user_id
        )
        if search:
            stmt = stmt.filter(
                or_(
                    db_models.CodeSubmission.project_name.ilike(f"%{search}%"),
                    cast(db_models.CodeSubmission.id, String).ilike(f"%{search}%"),
                )
            )
        result = await self.db.execute(stmt)
        return result.scalar_one() or 0

    async def delete(self, submission_id: uuid.UUID) -> bool:
        submission = await self.get_submission(submission_id)
        if not submission:
            return False
        await self.db.delete(submission)
        await self.db.commit()
        logger.info(
            f"Successfully deleted submission {submission_id} and all related data."
        )
        return True
