# src/app/core/services/submission_service.py

import logging
import uuid
import datetime
from typing import List, Dict, Any, Optional

from fastapi import UploadFile, HTTPException, status

from app.infrastructure.database.repositories.submission_repo import SubmissionRepository
from app.infrastructure.messaging.publisher import publish_message
from app.config.config import settings
from app.shared.lib.git import clone_repo_and_get_files
from app.shared.lib.archive import extract_archive_to_files, is_archive_filename
from app.shared.lib.files import get_language_from_filename
from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)

class SubmissionService:
    """
    Handles the business logic for creating submissions, managing their lifecycle, and retrieving results.
    """
    def __init__(self, repo: SubmissionRepository):
        self.repo = repo

    async def _process_and_create_submission(
        self, files_data: List[Dict[str, Any]], project_name: str, user_id: int, frameworks: List[str],
        excluded_files: List[str], main_llm_id: uuid.UUID, specialized_llm_id: uuid.UUID,
        correlation_id: str, repo_url: Optional[str] = None
    ) -> db_models.CodeSubmission:
        """A private helper to process submission data, create a DB record, and publish a message."""
        logger.info(
            "Processing and creating new submission.",
            extra={
                "project_name": project_name,
                "user_id": user_id,
                "file_count": len(files_data),
                "repo_url": repo_url or "N/A"
            }
        )
        if not files_data:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No files were successfully processed for analysis.")

        submission = await self.repo.create_submission(
            user_id=user_id, project_name=project_name, repo_url=repo_url, files=files_data,
            frameworks=frameworks, excluded_files=excluded_files, main_llm_id=main_llm_id,
            specialized_llm_id=specialized_llm_id
        )
        publish_message(
            queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
            message_body={"submission_id": str(submission.id)},
            correlation_id=correlation_id
        )
        logger.info(f"Published submission {submission.id} to RabbitMQ.", extra={"correlation_id": correlation_id, "submission_id": str(submission.id)})
        return submission

    async def create_from_uploads(self, *, files: List[UploadFile], **kwargs) -> db_models.CodeSubmission:
        """Handles submission from direct file uploads."""
        logger.info("Creating submission from file uploads.", extra={"file_count": len(files)})
        files_data = []
        for file in files:
            if not file.filename:
                continue
            if is_archive_filename(file.filename):
                raise HTTPException(
                    status_code=400,
                    detail=f"Archive file '{file.filename}' submitted incorrectly. Use the 'Upload Archive' option."
                )
            content_bytes = await file.read()
            try:
                content_str = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                content_str = content_bytes.decode("latin-1")
            
            files_data.append({
                "file_path": file.filename, # MODIFIED: Renamed 'path' to 'file_path'
                "content": content_str.replace("\x00", ""),
                "language": get_language_from_filename(file.filename) or "unknown"
            })
        return await self._process_and_create_submission(files_data=files_data, **kwargs)

    async def create_from_git(self, *, repo_url: str, **kwargs) -> db_models.CodeSubmission:
        """Handles submission from a Git repository."""
        logger.info("Creating submission from Git repository.", extra={"repo_url": repo_url})
        files_data = clone_repo_and_get_files(repo_url)
        return await self._process_and_create_submission(files_data=files_data, repo_url=repo_url, **kwargs)

    async def create_from_archive(self, *, archive_file: UploadFile, **kwargs) -> db_models.CodeSubmission:
        """Handles submission from an archive file."""
        logger.info("Creating submission from archive file.", extra={"filename": archive_file.filename})
        files_data = extract_archive_to_files(archive_file)
        return await self._process_and_create_submission(files_data=files_data, **kwargs)
    
    async def get_submission_status(self, submission_id: uuid.UUID) -> db_models.CodeSubmission:
        """Retrieves the status and basic details of a submission."""
        logger.info("Getting submission status.", extra={"submission_id": str(submission_id)})
        submission = await self.repo.get_submission(submission_id)
        if not submission:
            logger.warning("Submission not found.", extra={"submission_id": str(submission_id)})
            raise HTTPException(status_code=404, detail="Submission not found")
        return submission

    async def approve_submission(self, submission_id: uuid.UUID, user: db_models.User) -> None:
        """Approves a submission that is pending cost approval, queueing it for analysis."""
        logger.info("Attempting to approve submission.", extra={"submission_id": str(submission_id), "user_id": user.id})
        submission = await self.get_submission_status(submission_id)
        if submission.user_id != user.id and not user.is_superuser:
            raise HTTPException(status_code=403, detail="Not authorized to approve this submission")
        if submission.status != "PENDING_COST_APPROVAL":
            raise HTTPException(status_code=400, detail=f"Submission is not pending approval. Current status: {submission.status}")
        
        publish_message(settings.RABBITMQ_APPROVAL_QUEUE, {"submission_id": str(submission.id), "action": "resume_analysis"})
        await self.repo.update_status(submission_id, "Approved - Queued")
        logger.info("Submission approved and queued for processing.", extra={"submission_id": str(submission_id)})

    async def cancel_submission(self, submission_id: uuid.UUID, user: db_models.User) -> None:
        """Cancels a submission that is pending cost approval."""
        logger.info("Attempting to cancel submission.", extra={"submission_id": str(submission_id), "user_id": user.id})
        submission = await self.get_submission_status(submission_id)
        if submission.user_id != user.id and not user.is_superuser:
            raise HTTPException(status_code=403, detail="Not authorized to cancel this submission")
        if submission.status != "PENDING_COST_APPROVAL":
            raise HTTPException(status_code=400, detail=f"Submission cannot be cancelled. Current status: {submission.status}")
        
        await self.repo.update_status(submission_id, "Cancelled")
        logger.info(f"User {user.id} cancelled submission {submission_id}.")
        
    async def queue_remediation(self, submission_id: uuid.UUID, remediation_request: api_models.RemediationRequest, user: db_models.User, correlation_id: str) -> None:
        """Queues a completed submission for the remediation workflow."""
        logger.info(
            "Attempting to queue remediation.", 
            extra={
                "submission_id": str(submission_id), 
                "user_id": user.id, 
                "categories": remediation_request.categories_to_fix
            }
        )
        submission = await self.repo.get_submission(submission_id)
        if not submission:
            raise HTTPException(status_code=404, detail="Submission not found")
        if submission.user_id != user.id and not user.is_superuser:
            raise HTTPException(status_code=403, detail="Not authorized to remediate this submission")
        if submission.status not in ["Completed", "Remediation-Failed"]:
            raise HTTPException(status_code=400, detail=f"Remediation can only be started for submissions with status 'Completed' or 'Remediation-Failed'. Current status: {submission.status}")
        
        message = {"submission_id": str(submission.id), "action": "trigger_remediation", "categories_to_fix": remediation_request.categories_to_fix}
        publish_message(settings.RABBITMQ_REMEDIATION_QUEUE, message, correlation_id)
        await self.repo.update_status(submission_id, "Queued for Remediation")
        logger.info("Remediation queued successfully.", extra={"submission_id": str(submission_id)})
        
    async def delete_submission(self, submission_id: uuid.UUID) -> None:
        """Deletes a submission and all its associated data (findings, files, etc.)."""
        logger.info("Attempting to delete submission.", extra={"submission_id": str(submission_id)})
        deleted = await self.repo.delete(submission_id)
        if not deleted:
            logger.warning("Submission not found for deletion.", extra={"submission_id": str(submission_id)})
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Submission not found")
        logger.info("Submission deleted successfully.", extra={"submission_id": str(submission_id)})
    
    async def get_paginated_history(self, user_id: int, skip: int, limit: int, search: Optional[str]) -> api_models.PaginatedSubmissionHistoryResponse:
        """Retrieves a paginated list of submission history for a user."""
        logger.debug("Fetching paginated submission history for user.", extra={"user_id": user_id, "skip": skip, "limit": limit})
        total = await self.repo.get_history_count(user_id, search)
        items_raw = await self.repo.get_paginated_history(user_id, skip, limit, search)
        history_items = [api_models.SubmissionHistoryItem(**item) for item in items_raw]
        return api_models.PaginatedSubmissionHistoryResponse(items=history_items, total=total)
        
    async def get_paginated_results(self, user_id: int, skip: int, limit: int, search: Optional[str]) -> api_models.PaginatedResultsResponse:
        """Retrieves a paginated list of completed results for a user."""
        logger.debug("Fetching paginated results for user.", extra={"user_id": user_id, "skip": skip, "limit": limit})
        total = await self.repo.get_results_count(user_id, search)
        items_raw = await self.repo.get_paginated_results(user_id, skip, limit, search)
        result_items = [api_models.ResultIndexItem(**item) for item in items_raw]
        return api_models.PaginatedResultsResponse(items=result_items, total=total)

    async def get_llm_interactions(self, user_id: int) -> List[db_models.LLMInteraction]:
        """Retrieves all LLM interactions for a given user."""
        logger.debug("Fetching all LLM interactions for user.", extra={"user_id": user_id})
        return await self.repo.get_llm_interactions_for_user(user_id)

    async def get_results(self, submission_id: uuid.UUID) -> api_models.AnalysisResultDetailResponse:
        """Assembles the full, detailed analysis result for a submission."""
        logger.info("Assembling full analysis results.", extra={"submission_id": str(submission_id)})
        submission_db = await self.repo.get_submission(submission_id)
        if not submission_db:
            raise HTTPException(status_code=404, detail="Submission not found")

        if submission_db.status not in ["Completed", "Remediation-Completed", "Remediation-Failed"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Submission analysis is not yet completed. Current status: '{submission_db.status}'."
            )
        
        summary_report = self._build_summary_report(submission_db)
        original_code_map_dict = {file.file_path: file.content for file in submission_db.files} if submission_db.files else {}

        return api_models.AnalysisResultDetailResponse(
            status=submission_db.status,
            impact_report=submission_db.impact_report,
            sarif_report=submission_db.sarif_report,
            summary_report=summary_report,
            original_code_map=original_code_map_dict,
            fixed_code_map=submission_db.fixed_code_map
        )

    def _build_summary_report(self, submission: "db_models.CodeSubmission") -> api_models.SummaryReportResponse:
        """Private helper to encapsulate the logic for creating the summary report."""
        excluded_files_set = set(submission.excluded_files or [])
    
        analyzed_files_db = [
            file for file in submission.files if file.file_path not in excluded_files_set
        ]
        findings_from_analyzed_files = [
            finding for finding in submission.findings if finding.file_path not in excluded_files_set
        ]

        findings_by_file: Dict[str, List[db_models.VulnerabilityFinding]] = {}
        for finding_db_item in findings_from_analyzed_files:
            findings_by_file.setdefault(finding_db_item.file_path, []).append(finding_db_item)

        file_data_map: Dict[str, db_models.SubmittedFile] = {
            file_db.file_path: file_db for file_db in analyzed_files_db
        }
        
        all_involved_paths = sorted(list(set(file_data_map.keys()).union(set(findings_by_file.keys()))))

        files_analyzed_report_items: List[api_models.SubmittedFileReportItem] = []
        for path in all_involved_paths:
            file_info = file_data_map.get(path)
            file_findings = findings_by_file.get(path, [])
            file_findings_response = [api_models.VulnerabilityFindingResponse.from_orm(f) for f in file_findings]
            files_analyzed_report_items.append(
                api_models.SubmittedFileReportItem(
                    file_path=path, findings=file_findings_response,
                    language=file_info.language if file_info else "unknown",
                    analysis_summary=file_info.analysis_summary if file_info else None,
                    identified_components=file_info.identified_components if file_info else [],
                    asvs_analysis=file_info.asvs_analysis if file_info else None,
                )
            )

        sev_counts_obj = api_models.SeverityCountsResponse()
        for finding_db_item in findings_from_analyzed_files:
            sev = finding_db_item.severity.upper()
            if sev == "CRITICAL": sev_counts_obj.CRITICAL += 1
            elif sev == "HIGH": sev_counts_obj.HIGH += 1
            elif sev == "MEDIUM": sev_counts_obj.MEDIUM += 1
            elif sev == "LOW": sev_counts_obj.LOW += 1
            elif sev == "INFORMATIONAL": sev_counts_obj.INFORMATIONAL += 1

        summary_response_obj = api_models.SummaryResponse(
            total_findings_count=len(findings_from_analyzed_files),
            files_analyzed_count=len(files_analyzed_report_items),
            severity_counts=sev_counts_obj
        )
        
        primary_language = analyzed_files_db[0].language if analyzed_files_db else "N/A"

        return api_models.SummaryReportResponse(
            submission_id=submission.id,
            project_name=submission.project_name,
            primary_language=primary_language,
            selected_frameworks=submission.frameworks or [],
            analysis_timestamp=submission.completed_at,
            summary=summary_response_obj,
            overall_risk_score=api_models.OverallRiskScoreResponse(score=str(submission.risk_score or 0), severity="N/A")
        )