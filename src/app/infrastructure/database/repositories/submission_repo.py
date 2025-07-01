# src/app/infrastructure/database/repositories/submission_repo.py

import logging
import uuid
import datetime
from typing import List, Dict, Optional, Any

from sqlalchemy import String, case, cast, func, select, update, or_
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
        workflow_mode: str,
    ) -> db_models.CodeSubmission:
        """Creates a new CodeSubmission and its associated SubmittedFile records in the database."""
        logger.info(
            "Creating CodeSubmission entry in DB.",
            extra={"user_id": user_id, "project_name": project_name}
        )
        submission = db_models.CodeSubmission(
            user_id=user_id,
            project_name=project_name,
            repo_url=repo_url,
            status="Pending",
            frameworks=frameworks,
            excluded_files=excluded_files,
            main_llm_config_id=main_llm_id,
            specialized_llm_config_id=specialized_llm_id,
            workflow_mode=workflow_mode,
        )
        self.db.add(submission)
        await self.db.flush()
        db_files = [
            db_models.SubmittedFile(submission_id=submission.id, **f) for f in files
        ]
        self.db.add_all(db_files)
        await self.db.commit()
        await self.db.refresh(submission)
        logger.info("Successfully created submission in DB.", extra={"submission_id": str(submission.id)})
        return submission

    async def get_submission(
        self, submission_id: uuid.UUID
    ) -> Optional[db_models.CodeSubmission]:
        """
        Retrieves a single submission by its ID, eagerly loading related files,
        findings, and fixes for efficiency.
        """
        logger.debug("Fetching submission from DB.", extra={"submission_id": str(submission_id)})
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
        """Retrieves only the SubmittedFile records for a given submission."""
        logger.debug("Fetching submitted files for submission.", extra={"submission_id": str(submission_id)})
        result = await self.db.execute(
            select(db_models.SubmittedFile).filter(
                db_models.SubmittedFile.submission_id == submission_id
            )
        )
        return list(result.scalars().all())

    async def update_status(self, submission_id: uuid.UUID, status: str):
        """Updates the status of a single submission."""
        logger.info("Updating submission status in DB.", extra={"submission_id": str(submission_id), "new_status": status})
        stmt = (
            update(db_models.CodeSubmission)
            .where(db_models.CodeSubmission.id == submission_id)
            .values(status=status)
        )
        await self.db.execute(stmt)
        await self.db.commit()

    async def update_for_remediation(self, submission_id: uuid.UUID):
        """Updates the status and workflow mode for a remediation run."""
        logger.info(
            "Updating submission for remediation.",
            extra={"submission_id": str(submission_id)},
        )
        stmt = (
            update(db_models.CodeSubmission)
            .where(db_models.CodeSubmission.id == submission_id)
            .values(status="Queued for Remediation", workflow_mode="remediate")
        )
        await self.db.execute(stmt)
        await self.db.commit()

    async def save_llm_interaction(
        self, interaction_data: agent_schemas.LLMInteraction
    ):
        """Saves a single LLM interaction record to the database."""
        # Use debug level to avoid excessive logging in production
        logger.debug(
            "Saving LLM interaction to DB.",
            extra={
                "submission_id": str(interaction_data.submission_id),
                "agent_name": interaction_data.agent_name,
                "file_path": interaction_data.file_path
            }
        )
        db_interaction = db_models.LLMInteraction(**interaction_data.model_dump())
        self.db.add(db_interaction)
        await self.db.commit()

    async def save_findings(
        self,
        submission_id: uuid.UUID,
        findings: List[agent_schemas.VulnerabilityFinding],
    ) -> List[db_models.VulnerabilityFinding]:
        """Saves a list of vulnerability findings for a submission."""
        if not findings:
            return []
        logger.info(
            "Saving vulnerability findings to DB.",
            extra={"submission_id": str(submission_id), "finding_count": len(findings)}
        )
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
        """Saves a single code fix suggestion, linked to a specific finding."""
        logger.debug("Saving fix suggestion to DB.", extra={"finding_id": finding_id})
        fix = db_models.FixSuggestion(
            finding_id=finding_id,
            description=suggestion.description,
            original_snippet=suggestion.original_snippet, # ADDED
            suggested_fix=suggestion.code,
        )
        self.db.add(fix)
        await self.db.commit()

    async def update_cost_and_status(
        self, submission_id: uuid.UUID, status: str, estimated_cost: Dict[str, Any]
    ):
        """Atomically updates the status and the estimated cost of a submission."""
        logger.info(
            "Updating cost and status in DB.",
            extra={
                "submission_id": str(submission_id),
                "new_status": status,
                "total_estimated_cost": estimated_cost.get("total_estimated_cost")
            }
        )
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
        """Saves the final analysis reports, sets the completion timestamp, and updates the status."""
        logger.info("Saving final reports and status to DB.", extra={"submission_id": str(submission_id), "new_status": status})
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
        """Saves the map of fixed code and updates the submission status after remediation."""
        logger.info("Saving remediated code map and status to DB.", extra={"submission_id": str(submission_id), "new_status": status})
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

    async def get_paginated_results(self, user_id: int, skip: int, limit: int, search: Optional[str]) -> List[Dict[str, Any]]:
        """
        Retrieves a paginated list of completed submissions with aggregated finding counts.
        """
        finding_counts_subquery = (
            select(
                db_models.VulnerabilityFinding.submission_id,
                func.count(db_models.VulnerabilityFinding.id).label("total_findings"),
                func.sum(case((func.upper(db_models.VulnerabilityFinding.severity) == 'CRITICAL', 1), else_=0)).label("critical_findings"),
                func.sum(case((func.upper(db_models.VulnerabilityFinding.severity) == 'HIGH', 1), else_=0)).label("high_findings"),
                func.sum(case((func.upper(db_models.VulnerabilityFinding.severity) == 'MEDIUM', 1), else_=0)).label("medium_findings"),
                func.sum(case((func.upper(db_models.VulnerabilityFinding.severity) == 'LOW', 1), else_=0)).label("low_findings"),
            )
            .group_by(db_models.VulnerabilityFinding.submission_id).subquery()
        )
        stmt = (
            select(db_models.CodeSubmission, finding_counts_subquery.c.total_findings, finding_counts_subquery.c.critical_findings, finding_counts_subquery.c.high_findings, finding_counts_subquery.c.medium_findings, finding_counts_subquery.c.low_findings)
            .outerjoin(finding_counts_subquery, db_models.CodeSubmission.id == finding_counts_subquery.c.submission_id)
            .where(db_models.CodeSubmission.user_id == user_id, db_models.CodeSubmission.status.in_(["Completed", "Remediation-Completed"]))
        )
        if search:
            stmt = stmt.filter(or_(db_models.CodeSubmission.project_name.ilike(f"%{search}%"), cast(db_models.CodeSubmission.id, String).ilike(f"%{search}%")))
        stmt = stmt.order_by(db_models.CodeSubmission.completed_at.desc().nulls_last()).offset(skip).limit(limit)
        
        result = await self.db.execute(stmt)
        results_list = []
        for row in result.all():
            sub, total, critical, high, medium, low = row
            critical_count, high_count, medium_count, low_count = critical or 0, high or 0, medium or 0, low or 0
            risk_score = (critical_count * 10) + (high_count * 5) + (medium_count * 2) + (low_count * 1)
            results_list.append({
                "submission_id": sub.id, "project_name": sub.project_name, "completed_at": sub.completed_at,
                "total_findings": total or 0, "critical_findings": critical_count, "high_findings": high_count,
                "medium_findings": medium_count, "low_findings": low_count, "risk_score": risk_score,
            })
        return results_list

    async def get_results_count(self, user_id: int, search: Optional[str] = None) -> int:
        """Counts the total number of completed submissions for a specific user."""
        stmt = select(func.count(db_models.CodeSubmission.id))\
            .where(db_models.CodeSubmission.user_id == user_id, db_models.CodeSubmission.status.in_(["Completed", "Remediation-Completed"]))
        if search:
            stmt = stmt.filter(or_(db_models.CodeSubmission.project_name.ilike(f"%{search}%"), cast(db_models.CodeSubmission.id, String).ilike(f"%{search}%")))
        result = await self.db.execute(stmt)
        return result.scalar_one() or 0

    async def get_llm_interactions_for_user(self, user_id: int) -> List[db_models.LLMInteraction]:
        """Retrieves all LLM interactions for a given user, ordered by most recent."""
        stmt = (
            select(db_models.LLMInteraction)
            .join(db_models.CodeSubmission, db_models.LLMInteraction.submission_id == db_models.CodeSubmission.id)
            .where(db_models.CodeSubmission.user_id == user_id)
            .order_by(db_models.LLMInteraction.timestamp.desc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

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
        """Deletes a submission and all its cascaded children (files, findings, etc.)."""
        logger.info("Attempting to delete submission from DB.", extra={"submission_id": str(submission_id)})
        submission = await self.get_submission(submission_id)
        if not submission:
            logger.warning("Submission not found for deletion.", extra={"submission_id": str(submission_id)})
            return False
        await self.db.delete(submission)
        await self.db.commit()
        logger.info(
            f"Successfully deleted submission {submission_id} and all related data."
        )
        return True
