# src/app/core/services/submission_service.py

import logging
import uuid
from typing import List, Dict, Any, Optional

from fastapi import UploadFile, HTTPException, status

from app.infrastructure.database.repositories.submission_repo import (
    SubmissionRepository,
)
from app.infrastructure.messaging.publisher import publish_message
from app.config.config import settings
from app.shared.lib.git_utils import clone_repo_and_get_files
from app.shared.lib.archive_utils import extract_archive_to_files, is_archive_filename
from app.shared.lib.file_utils import get_language_from_filename
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
        self,
        files_data: List[Dict[str, Any]],
        project_name: str,
        user_id: int,
        frameworks: List[str],
        excluded_files: List[str],
        main_llm_id: uuid.UUID,
        specialized_llm_id: uuid.UUID,
        correlation_id: str,
        repo_url: Optional[str] = None,
    ) -> db_models.CodeSubmission:
        if not files_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No files were successfully processed for analysis.",
            )

        submission = await self.repo.create_submission(
            user_id=user_id,
            project_name=project_name,
            repo_url=repo_url,
            files=files_data,
            frameworks=frameworks,
            excluded_files=excluded_files,
            main_llm_id=main_llm_id,
            specialized_llm_id=specialized_llm_id,
        )
        publish_message(
            queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
            message_body={"submission_id": str(submission.id)},
            correlation_id=correlation_id,
        )
        logger.info(
            f"Published submission {submission.id} to RabbitMQ.",
            extra={"correlation_id": correlation_id},
        )
        return submission

    async def create_from_uploads(
        self, *, files: List[UploadFile], **kwargs
    ) -> db_models.CodeSubmission:
        files_data = []
        for file in files:
            if not file.filename:
                continue
            if is_archive_filename(file.filename):
                raise HTTPException(
                    status_code=400,
                    detail=f"Archive file '{file.filename}' submitted incorrectly. Use the 'Upload Archive' option.",
                )
            content_bytes = await file.read()
            try:
                content_str = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                content_str = content_bytes.decode("latin-1")
            files_data.append(
                {
                    "path": file.filename,
                    "content": content_str.replace("\x00", ""),
                    "language": get_language_from_filename(file.filename) or "unknown",
                }
            )
        return await self._process_and_create_submission(
            files_data=files_data, **kwargs
        )

    async def create_from_git(
        self, *, repo_url: str, **kwargs
    ) -> db_models.CodeSubmission:
        files_data = clone_repo_and_get_files(repo_url)
        return await self._process_and_create_submission(
            files_data=files_data, repo_url=repo_url, **kwargs
        )

    async def create_from_archive(
        self, *, archive_file: UploadFile, **kwargs
    ) -> db_models.CodeSubmission:
        files_data = extract_archive_to_files(archive_file)
        return await self._process_and_create_submission(
            files_data=files_data, **kwargs
        )

    async def get_submission_status(
        self, submission_id: uuid.UUID
    ) -> db_models.CodeSubmission:
        submission = await self.repo.get_submission(submission_id)
        if not submission:
            raise HTTPException(status_code=404, detail="Submission not found")
        return submission

    async def approve_submission(
        self, submission_id: uuid.UUID, user: db_models.User
    ) -> None:
        submission = await self.get_submission_status(submission_id)
        if submission.user_id != user.id and not user.is_superuser:
            raise HTTPException(
                status_code=403, detail="Not authorized to approve this submission"
            )
        if submission.status != "PENDING_COST_APPROVAL":
            raise HTTPException(
                status_code=400,
                detail=f"Submission is not pending approval. Current status: {submission.status}",
            )

        publish_message(
            settings.RABBITMQ_APPROVAL_QUEUE,
            {"submission_id": str(submission.id), "action": "resume_analysis"},
        )
        await self.repo.update_status(submission_id, "Approved - Queued")

    async def cancel_submission(
        self, submission_id: uuid.UUID, user: db_models.User
    ) -> None:
        submission = await self.get_submission_status(submission_id)
        if submission.user_id != user.id and not user.is_superuser:
            raise HTTPException(
                status_code=403, detail="Not authorized to cancel this submission"
            )
        if submission.status != "PENDING_COST_APPROVAL":
            raise HTTPException(
                status_code=400,
                detail=f"Submission cannot be cancelled. Current status: {submission.status}",
            )

        await self.repo.update_status(submission_id, "Cancelled")
        logger.info(f"User {user.id} cancelled submission {submission_id}.")

    async def queue_remediation(
        self,
        submission_id: uuid.UUID,
        remediation_request: api_models.RemediationRequest,
        user: db_models.User,
        correlation_id: str,
    ) -> None:
        submission = await self.repo.get_submission(submission_id)
        if not submission:
            raise HTTPException(status_code=404, detail="Submission not found")
        if submission.user_id != user.id and not user.is_superuser:
            raise HTTPException(
                status_code=403, detail="Not authorized to remediate this submission"
            )
        if submission.status not in ["Completed", "Remediation-Failed"]:
            raise HTTPException(
                status_code=400,
                detail=f"Remediation can only be started for submissions with status 'Completed' or 'Remediation-Failed'. Current status: {submission.status}",
            )

        message = {
            "submission_id": str(submission.id),
            "action": "trigger_remediation",
            "categories_to_fix": remediation_request.categories_to_fix,
        }
        publish_message(settings.RABBITMQ_REMEDIATION_QUEUE, message, correlation_id)
        await self.repo.update_status(submission_id, "Queued for Remediation")

    async def delete_submission(self, submission_id: uuid.UUID) -> None:
        deleted = await self.repo.delete(submission_id)
        if not deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Submission not found"
            )
