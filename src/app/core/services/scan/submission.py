"""Scan-submission service: creates Scan + Snapshot + Outbox rows
and publishes the kickoff message to RabbitMQ.

Split out of `core/services/scan_service.py` (2026-04-26). Method
bodies are verbatim copies — no logic change.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, UploadFile, status

from app.config.config import settings
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_outbox_repo import (
    ScanOutboxRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.messaging.publisher import publish_message
from app.shared.lib.archive import extract_archive_to_files, is_archive_filename
from app.shared.lib.files import get_language_from_filename
from app.shared.lib.git import clone_repo_and_get_files

logger = logging.getLogger(__name__)


class ScanSubmissionService:
    """New-scan creation + initial outbox-publish path.

    `__init__` constructs the outbox repo from the SAME session as the
    scan repo so `_process_and_launch_scan` can write Scan +
    CodeSnapshot + ScanOutbox atomically (G-split-2 from the threat
    model).
    """

    def __init__(self, repo: ScanRepository):
        self.repo = repo
        self.outbox = ScanOutboxRepository(repo.db)

    async def _process_and_launch_scan(
        self,
        project_name: str,
        user_id: int,
        files_data: List[Dict[str, Any]],
        scan_type: str,
        correlation_id: str,
        utility_llm_config_id: uuid.UUID,
        reasoning_llm_config_id: uuid.UUID,
        frameworks: List[str],
        repo_url: Optional[str] = None,
        selected_files: Optional[List[str]] = None,
    ) -> db_models.Scan:
        """
        A private helper to process submission data, create all necessary DB records,
        and publish a message to kick off the workflow.
        """
        if selected_files:
            # Filter the files_data to only include user-selected files
            selected_files_set = set(selected_files)
            original_count = len(files_data)
            files_data = [f for f in files_data if f["path"] in selected_files_set]
            logger.info(
                f"Filtered submission based on user selection. "
                f"Original files: {original_count}, Selected files: {len(files_data)}."
            )

        if not files_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No files were provided for analysis.",
            )

        # 1. Get or create the project
        project = await self.repo.get_or_create_project(
            name=project_name, user_id=user_id, repo_url=repo_url
        )

        # 2. Get or create deduplicated source code files
        file_hashes = await self.repo.get_or_create_source_files(files_data)

        # 3. Create the file map for the snapshot {path: hash}
        file_map = {
            file_data["path"]: file_hash
            for file_data, file_hash in zip(files_data, file_hashes)
        }

        # 4. Create the Scan record
        scan = await self.repo.create_scan(
            project_id=project.id,
            user_id=user_id,
            scan_type=scan_type,
            utility_llm_config_id=utility_llm_config_id,
            reasoning_llm_config_id=reasoning_llm_config_id,
            frameworks=frameworks,
        )

        # 5. Create the Code Snapshot linked to the scan
        await self.repo.create_code_snapshot(
            scan_id=scan.id, file_map=file_map, snapshot_type="ORIGINAL_SUBMISSION"
        )

        # 6. Add "QUEUED" event to the timeline
        await self.repo.create_scan_event(
            scan_id=scan.id, stage_name="QUEUED", status="COMPLETED"
        )

        # 7. Persist an outbox row FIRST, so the sweep task can retry the
        # publish later if RabbitMQ is down right now.
        payload = {"scan_id": str(scan.id)}
        outbox_row = await self.outbox.enqueue(
            scan_id=scan.id,
            queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
            payload=payload,
        )

        # 8. Attempt the publish inline. Best-effort: on failure, the outbox
        # sweeper will re-publish.
        published = await publish_message(
            queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
            message_body=payload,
            correlation_id=correlation_id,
        )
        if published:
            await self.outbox.mark_published(outbox_row.id)
            logger.info(
                f"Published scan {scan.id} to RabbitMQ.",
                extra={"correlation_id": correlation_id, "scan_id": str(scan.id)},
            )
        else:
            await self.outbox.record_failed_attempt(outbox_row.id)
            logger.warning(
                f"Scan {scan.id} published to outbox but RabbitMQ publish failed; "
                f"sweeper will retry.",
                extra={"correlation_id": correlation_id, "scan_id": str(scan.id)},
            )

        return scan

    async def create_scan_from_uploads(
        self, *, files: List[UploadFile], **kwargs
    ) -> db_models.Scan:
        """Handles submission from direct file uploads."""
        logger.info(
            "Creating scan from file uploads.", extra={"file_count": len(files)}
        )
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
                content_str = content_bytes.decode("latin-1", errors="ignore")

            files_data.append(
                {
                    "path": file.filename,
                    "content": content_str.replace("\x00", ""),
                    "language": get_language_from_filename(file.filename) or "unknown",
                }
            )

        return await self._process_and_launch_scan(files_data=files_data, **kwargs)

    async def create_scan_from_git(self, *, repo_url: str, **kwargs) -> db_models.Scan:
        """Handles submission from a Git repository."""
        logger.info("Creating scan from Git repository.", extra={"repo_url": repo_url})
        files_data = clone_repo_and_get_files(repo_url)
        return await self._process_and_launch_scan(
            files_data=files_data, repo_url=repo_url, **kwargs
        )

    async def create_scan_from_archive(
        self, *, archive_file: UploadFile, **kwargs
    ) -> db_models.Scan:
        """Handles submission from an archive file."""
        logger.info(
            "Creating scan from archive file.",
            extra={"filename": archive_file.filename},
        )
        files_data = extract_archive_to_files(archive_file)
        return await self._process_and_launch_scan(files_data=files_data, **kwargs)
