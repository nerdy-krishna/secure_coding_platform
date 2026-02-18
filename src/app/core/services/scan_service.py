import logging
import uuid
from typing import List, Dict, Any, Optional

from fastapi import UploadFile, HTTPException, status

from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.messaging.publisher import publish_message
from app.config.config import settings
from app.shared.lib.git import clone_repo_and_get_files
from app.shared.lib.archive import extract_archive_to_files, is_archive_filename
from app.shared.lib.files import get_language_from_filename
from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models
from app.core import schemas as agent_schemas
from app.shared.lib.reporting import (
    create_executive_summary_html,
    generate_pdf_from_html,
)
from itertools import groupby
from operator import attrgetter

logger = logging.getLogger(__name__)


class SubmissionService:
    """
    Handles the business logic for creating projects and scans, managing their lifecycle,
    and retrieving results.
    """

    def __init__(self, repo: ScanRepository):
        self.repo = repo

    async def _process_and_launch_scan(
        self,
        project_name: str,
        user_id: int,
        files_data: List[Dict[str, Any]],
        scan_type: str,
        correlation_id: str,
        utility_llm_config_id: uuid.UUID,
        fast_llm_config_id: uuid.UUID,
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
            fast_llm_config_id=fast_llm_config_id,
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

        # 7. Publish message to worker queue
        publish_message(
            queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
            message_body={"scan_id": str(scan.id)},
            correlation_id=correlation_id,
        )
        logger.info(
            f"Published scan {scan.id} to RabbitMQ.",
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

    async def get_scan_status(self, scan_id: uuid.UUID) -> db_models.Scan:
        """Retrieves the status and basic details of a scan."""
        logger.info("Getting scan status.", extra={"scan_id": str(scan_id)})
        scan = await self.repo.get_scan(scan_id)
        if not scan:
            logger.warning("Scan not found.", extra={"scan_id": str(scan_id)})
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan

    async def approve_scan(self, scan_id: uuid.UUID, user: db_models.User) -> None:
        """Approves a scan that is pending cost approval, queueing it for analysis."""
        logger.info(
            "Attempting to approve scan.",
            extra={"scan_id": str(scan_id), "user_id": user.id},
        )
        scan = await self.get_scan_status(scan_id)
        if scan.user_id != user.id and not user.is_superuser:
            raise HTTPException(
                status_code=403, detail="Not authorized to approve this scan"
            )
        if scan.status != "PENDING_COST_APPROVAL":
            raise HTTPException(
                status_code=400,
                detail=f"Scan is not pending approval. Current status: {scan.status}",
            )

        await self.repo.update_status(scan_id, "QUEUED_FOR_SCAN")
        await self.repo.create_scan_event(
            scan_id=scan_id, stage_name="QUEUED_FOR_SCAN", status="COMPLETED"
        )
        publish_message(
            settings.RABBITMQ_APPROVAL_QUEUE,
            {"scan_id": str(scan_id), "action": "resume_analysis"},
        )
        logger.info(
            "Scan approved and queued for processing.", extra={"scan_id": str(scan_id)}
        )

    async def cancel_scan(self, scan_id: uuid.UUID, user: db_models.User) -> None:
        """Cancels a scan, typically one that is pending approval."""
        logger.info(f"User {user.id} attempting to cancel scan {scan_id}.")
        scan = await self.repo.get_scan(scan_id)
        if not scan or (scan.user_id != user.id and not user.is_superuser):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        cancellable_statuses = [
            "QUEUED",
            "PENDING_COST_APPROVAL",
            "QUEUED_FOR_SCAN",
            "ANALYZING_CONTEXT",
            "RUNNING_AGENTS",
            "GENERATING_REPORTS",
        ]
        if scan.status not in cancellable_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan cannot be cancelled from its current state: {scan.status}",
            )

        await self.repo.update_status(scan_id, "CANCELLED")
        await self.repo.create_scan_event(
            scan_id=scan.id, stage_name="CANCELLED", status="COMPLETED"
        )
        logger.info(f"Scan {scan_id} has been cancelled by user {user.id}.")

    async def apply_fixes_for_scan(
        self, scan_id: uuid.UUID, user: db_models.User
    ) -> None:
        """Applies all suggested and verified fixes for a completed AUDIT_AND_REMEDIATE scan."""
        logger.info(f"User {user.id} initiating fix application for scan {scan_id}.")
        scan = await self.repo.get_scan_with_details(scan_id)

        if not scan or (scan.user_id != user.id and not user.is_superuser):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        if scan.scan_type != "AUDIT_AND_REMEDIATE" or scan.status != "COMPLETED":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Fixes can only be applied to completed 'Audit & Remediate' scans.",
            )

        original_snapshot = next(
            (s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"),
            None,
        )
        if not original_snapshot:
            raise HTTPException(
                status_code=500, detail="Original code snapshot not found."
            )

        content_map = await self.repo.get_source_files_by_hashes(
            list(original_snapshot.file_map.values())
        )
        live_codebase = {
            path: content_map.get(h, "")
            for path, h in original_snapshot.file_map.items()
        }

        findings_with_fixes = [f for f in scan.findings if f.fixes]

        for finding in findings_with_fixes:
            fix_data = finding.fixes
            if fix_data:
                original_snippet = fix_data.get("original_snippet")
                new_code = fix_data.get("code")

                if finding.file_path in live_codebase and original_snippet and new_code:
                    if original_snippet in live_codebase[finding.file_path]:
                        live_codebase[finding.file_path] = live_codebase[
                            finding.file_path
                        ].replace(original_snippet, new_code, 1)
                        logger.debug(
                            f"Applied fix for CWE-{finding.cwe} in {finding.file_path}"
                        )
                    else:
                        logger.warning(
                            f"Could not find snippet to apply fix for CWE-{finding.cwe} in {finding.file_path}"
                        )

        # Create a new snapshot with the updated code
        new_hashes = await self.repo.get_or_create_source_files(
            [
                {
                    "path": path,
                    "content": content,
                    "language": get_language_from_filename(path),
                }
                for path, content in live_codebase.items()
            ]
        )

        new_file_map = {
            path: file_hash for path, file_hash in zip(live_codebase.keys(), new_hashes)
        }

        await self.repo.create_code_snapshot(
            scan_id=scan.id, file_map=new_file_map, snapshot_type="POST_REMEDIATION"
        )
        await self.repo.update_status(scan_id, "REMEDIATION_COMPLETED")
        logger.info(
            f"All fixes applied for scan {scan_id}. Status set to REMEDIATION_COMPLETED."
        )

    async def get_scan_result(
        self, scan_id: uuid.UUID, user: db_models.User
    ) -> api_models.AnalysisResultDetailResponse:
        """
        Constructs the detailed analysis result for a given scan, including findings,
        code snapshots, and reports.
        """
        logger.info(f"User {user.id} requesting full result for scan {scan_id}.")
        scan = await self.repo.get_scan_with_details(scan_id)

        if not scan or (scan.user_id != user.id and not user.is_superuser):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        # --- ADD THIS LOGGING BLOCK ---
        logger.debug(
            f"[DEBUG] Fetched scan from DB. Findings loaded: {len(scan.findings)}. "
            f"Impact report loaded: {bool(scan.impact_report)}. Summary loaded: {bool(scan.summary)}.",
            extra={"scan_id": str(scan_id)},
        )
        # --- END LOGGING BLOCK ---

        original_code_map = {}
        fixed_code_map = {}
        original_snapshot = next(
            (s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"),
            None,
        )
        remediated_snapshot = next(
            (s for s in scan.snapshots if s.snapshot_type == "POST_REMEDIATION"), None
        )

        if original_snapshot:
            hashes = list(original_snapshot.file_map.values())
            content_map = await self.repo.get_source_files_by_hashes(hashes)
            original_code_map = {
                path: content_map.get(h, "")
                for path, h in original_snapshot.file_map.items()
            }

        if remediated_snapshot:
            hashes = list(remediated_snapshot.file_map.values())
            content_map = await self.repo.get_source_files_by_hashes(hashes)
            fixed_code_map = {
                path: content_map.get(h, "")
                for path, h in remediated_snapshot.file_map.items()
            }

        summary_report_response = None
        if scan.summary:
            files_analyzed_map: Dict[str, api_models.SubmittedFileReportItem] = {}

            # Use repository_map (if available) to initialize the file list
            # This ensures we account for skipped files.
            repository_map = scan.repository_map or {}
            all_files_in_scan = repository_map.get("files", {})

            for file_path, file_summary_dict in all_files_in_scan.items():
                skipped_reason = None
                if file_summary_dict.get("errors"):
                    skipped_reason = file_summary_dict["errors"][0]

                files_analyzed_map[file_path] = api_models.SubmittedFileReportItem(
                    file_path=file_path,
                    findings=[],
                    language=get_language_from_filename(file_path),
                    skipped_reason=skipped_reason,
                )

            # FIX: Use a robust groupby to associate findings with files.
            # Sort findings by file_path to prepare for grouping.
            sorted_findings = sorted(scan.findings, key=attrgetter("file_path"))

            # Group findings by file_path and populate the map.
            for file_path, group in groupby(
                sorted_findings, key=attrgetter("file_path")
            ):
                if file_path in files_analyzed_map:
                    findings_for_file = [
                        api_models.VulnerabilityFindingResponse.from_orm(f)
                        for f in group
                    ]
                    files_analyzed_map[file_path].findings.extend(findings_for_file)

            summary_dict = scan.summary.get("summary", {})
            risk_score_dict = scan.summary.get("overall_risk_score", {})

            summary_report_response = api_models.SummaryReportResponse(
                submission_id=scan.id,
                project_id=scan.project_id,
                project_name=scan.project.name if scan.project else "N/A",
                scan_type=scan.scan_type,
                selected_frameworks=scan.frameworks or [],
                analysis_timestamp=scan.completed_at,
                summary=api_models.SummaryResponse(**summary_dict),
                overall_risk_score=api_models.OverallRiskScoreResponse(
                    **risk_score_dict
                ),
                files_analyzed=list(files_analyzed_map.values()),
            )

        # --- ADD THIS LOGGING BLOCK ---
        if summary_report_response:
            total_findings_in_response = sum(
                len(f.findings) for f in summary_report_response.files_analyzed
            )
            logger.debug(
                f"[DEBUG] Assembled final response. Files in report: {len(summary_report_response.files_analyzed)}. "
                f"Total findings in response file list: {total_findings_in_response}.",
                extra={"scan_id": str(scan_id)},
            )
        # --- END LOGGING BLOCK ---

        return api_models.AnalysisResultDetailResponse(
            status=scan.status,
            impact_report=scan.impact_report,
            sarif_report=scan.sarif_report,
            summary_report=summary_report_response,
            original_code_map=original_code_map or None,
            fixed_code_map=fixed_code_map or None,
        )

    async def get_paginated_scans_for_project(
        self, project_id: uuid.UUID, user_id: int, skip: int, limit: int
    ) -> api_models.PaginatedScanHistoryResponse:
        """Retrieves a paginated list of scan history for a project."""
        project = await self.repo.get_project_by_id(project_id)
        if not project or project.user_id != user_id:
            raise HTTPException(
                status_code=404, detail="Project not found or not authorized."
            )

        total = await self.repo.get_scans_count_for_project(project_id)
        scans_raw = await self.repo.get_paginated_scans_for_project(
            project_id, skip, limit
        )

        history_items = [
            api_models.ScanHistoryItem.from_orm(scan) for scan in scans_raw
        ]
        return api_models.PaginatedScanHistoryResponse(items=history_items, total=total)

    async def get_paginated_user_scans(
        self,
        user_id: int,
        skip: int,
        limit: int,
        search: Optional[str],
        sort_order: str,
        status: Optional[str],
    ) -> api_models.PaginatedScanHistoryResponse:
        """Retrieves a paginated list of all scans for a user."""

        status_filters = []
        if status:
            if status == "In Progress":
                status_filters = [
                    "QUEUED",
                    "QUEUED_FOR_SCAN",
                    "ANALYZING_CONTEXT",
                    "RUNNING_AGENTS",
                    "GENERATING_REPORTS",
                ]
            elif status == "Completed":
                status_filters = ["COMPLETED", "REMEDIATION_COMPLETED"]
            elif status != "All":
                status_filters = [status.upper().replace(" ", "_")]

        total = await self.repo.get_scans_count_for_user(
            user_id, search, status_filters
        )
        scans_raw = await self.repo.get_paginated_scans_for_user(
            user_id, skip, limit, search, sort_order, status_filters
        )

        history_items = [
            api_models.ScanHistoryItem(
                id=scan.id,
                project_id=scan.project_id,
                project_name=scan.project.name,
                scan_type=scan.scan_type,
                status=scan.status,
                created_at=scan.created_at,
                completed_at=scan.completed_at,
                cost_details=scan.cost_details,
                events=[api_models.ScanEventItem.from_orm(e) for e in scan.events],
                has_sarif_report=bool(scan.sarif_report),
                has_impact_report=bool(scan.impact_report),
            )
            for scan in scans_raw
        ]
        return api_models.PaginatedScanHistoryResponse(items=history_items, total=total)

    async def search_projects(self, user_id: int, query: str) -> List[str]:
        """Searches project names for autocomplete."""
        projects = await self.repo.search_projects_by_name(
            user_id=user_id, name_query=query
        )
        return [p.name for p in projects]

    async def get_sarif_for_scan(
        self, scan_id: uuid.UUID, user: db_models.User
    ) -> Dict[str, Any]:
        """Retrieves just the SARIF report for a given scan, ensuring user has access."""
        scan = await self.repo.get_scan(scan_id)
        if not scan or (scan.user_id != user.id and not user.is_superuser):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )
        if not scan.sarif_report:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="SARIF report not available for this scan.",
            )
        return scan.sarif_report

    async def get_llm_interactions_for_scan(
        self, scan_id: uuid.UUID, user: db_models.User
    ) -> List[db_models.LLMInteraction]:
        """Gets all LLM interactions for a given scan, ensuring user has access."""
        logger.info(f"User {user.id} requesting LLM interactions for scan {scan_id}.")
        scan = await self.repo.get_scan(scan_id)
        if not scan or (scan.user_id != user.id and not user.is_superuser):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        return await self.repo.get_llm_interactions_for_scan(scan_id)

    async def get_paginated_projects(
        self, user_id: int, skip: int, limit: int, search: Optional[str]
    ) -> api_models.PaginatedProjectHistoryResponse:
        """Retrieves a paginated list of projects for a user."""
        total = await self.repo.get_projects_count(user_id, search)
        projects = await self.repo.get_paginated_projects(user_id, skip, limit, search)

        # This part can be optimized later if needed, but is fine for now
        project_items = []
        for project in projects:
            scans_raw = await self.repo.get_paginated_scans_for_project(
                project.id, 0, 5
            )  # Fetch latest 5 scans for preview
            scans = [
                api_models.ScanHistoryItem(
                    id=s.id,
                    project_id=s.project_id,
                    project_name=s.project.name,
                    scan_type=s.scan_type,
                    status=s.status,
                    created_at=s.created_at,
                    completed_at=s.completed_at,
                    cost_details=s.cost_details,
                    events=[api_models.ScanEventItem.from_orm(e) for e in s.events],
                    has_sarif_report=bool(s.sarif_report),
                    has_impact_report=bool(s.impact_report),
                )
                for s in scans_raw
            ]
            project_item = api_models.ProjectHistoryItem(
                id=project.id,
                name=project.name,
                repository_url=project.repository_url,
                created_at=project.created_at,
                updated_at=project.updated_at,
                scans=scans,
            )
            project_items.append(project_item)

        return api_models.PaginatedProjectHistoryResponse(
            items=project_items, total=total
        )

    async def delete_scan_by_id(self, scan_id: uuid.UUID, user: db_models.User):
        """Deletes a single scan, checking for superuser privileges."""
        if not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only superusers can delete scans.",
            )

        scan = await self.repo.get_scan(scan_id)
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found."
            )

        await self.repo.delete_scan(scan_id)
        logger.info(f"Superuser {user.id} deleted scan {scan_id}.")

    async def delete_project_by_id(self, project_id: uuid.UUID, user: db_models.User):
        """Deletes a project and all its associated scans, for superusers only."""
        if not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only superusers can delete projects.",
            )

        project = await self.repo.get_project_by_id(project_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Project not found."
            )

        await self.repo.delete_project(project_id)
        logger.info(
            f"Superuser {user.id} deleted project {project_id} and all associated scans."
        )

    async def apply_selective_fixes(
        self, scan_id: uuid.UUID, finding_ids: List[int], user: db_models.User
    ):
        """Applies fixes only for a selected list of finding IDs."""
        logger.info(
            f"User {user.id} initiating selective fix application for {len(finding_ids)} findings in scan {scan_id}."
        )
        scan = await self.repo.get_scan_with_details(scan_id)

        if not scan or (scan.user_id != user.id and not user.is_superuser):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        original_snapshot = next(
            (s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"),
            None,
        )
        if not original_snapshot:
            raise HTTPException(
                status_code=500, detail="Original code snapshot not found."
            )

        content_map = await self.repo.get_source_files_by_hashes(
            list(original_snapshot.file_map.values())
        )
        live_codebase = {
            path: content_map.get(h, "")
            for path, h in original_snapshot.file_map.items()
        }

        # Filter findings to only those selected for fixing
        findings_to_fix = [f for f in scan.findings if f.id in finding_ids and f.fixes]

        if not findings_to_fix:
            raise HTTPException(
                status_code=400, detail="No valid findings with fixes were selected."
            )

        for finding in findings_to_fix:
            fix_data = finding.fixes
            if fix_data:
                original_snippet = fix_data.get("original_snippet")
                new_code = fix_data.get("code")

                if finding.file_path in live_codebase and original_snippet and new_code:
                    if original_snippet in live_codebase[finding.file_path]:
                        live_codebase[finding.file_path] = live_codebase[
                            finding.file_path
                        ].replace(original_snippet, new_code, 1)
                        logger.debug(
                            f"Applied selective fix for CWE-{finding.cwe} in {finding.file_path}"
                        )
                    else:
                        logger.warning(
                            f"Could not find snippet to apply selective fix for CWE-{finding.cwe} in {finding.file_path}"
                        )

        # Create a new snapshot with the updated code
        new_hashes = await self.repo.get_or_create_source_files(
            [
                {
                    "path": path,
                    "content": content,
                    "language": get_language_from_filename(path),
                }
                for path, content in live_codebase.items()
            ]
        )

        new_file_map = {
            path: file_hash for path, file_hash in zip(live_codebase.keys(), new_hashes)
        }

        await self.repo.create_code_snapshot(
            scan_id=scan.id, file_map=new_file_map, snapshot_type="POST_REMEDIATION"
        )
        await self.repo.update_status(scan_id, "REMEDIATION_COMPLETED")
        logger.info(
            f"Selective fixes applied for scan {scan_id}. Status set to REMEDIATION_COMPLETED."
        )

    async def generate_executive_summary_pdf(
        self, scan_id: uuid.UUID, user: db_models.User
    ) -> Optional[bytes]:
        """Generates a PDF byte stream for the executive summary report."""
        scan = await self.repo.get_scan_with_details(scan_id)

        if not scan or (scan.user_id != user.id and not user.is_superuser):
            logger.warning(
                f"User {user.id} attempted to access PDF for unauthorized scan {scan_id}."
            )
            return None

        if not scan.impact_report or not scan.summary:
            logger.warning(
                f"PDF generation failed: Scan {scan_id} is missing impact or summary report data."
            )
            return None

        # Re-construct Pydantic models from the JSON data for type safety
        impact_report_data = scan.impact_report or {}
        impact_report_model = agent_schemas.ImpactReport(
            executive_summary=impact_report_data.get("executive_summary", "N/A"),
            vulnerability_overview=impact_report_data.get(
                "vulnerability_overview", "N/A"
            ),
            high_risk_findings_summary=impact_report_data.get(
                "high_risk_findings_summary", []
            ),
            remediation_strategy=impact_report_data.get("remediation_strategy", "N/A"),
            vulnerability_categories=impact_report_data.get(
                "vulnerability_categories", []
            ),
            estimated_remediation_effort=impact_report_data.get(
                "estimated_remediation_effort", "N/A"
            ),
            required_architectural_changes=impact_report_data.get(
                "required_architectural_changes", []
            ),
        )

        # Build the summary report model from all necessary sources
        summary_data_from_db = scan.summary or {}
        summary_report_model = api_models.SummaryReportResponse(
            submission_id=scan.id,
            project_id=scan.project_id,
            project_name=scan.project.name,
            scan_type=scan.scan_type,
            analysis_timestamp=scan.completed_at,
            selected_frameworks=scan.frameworks or [],
            summary=summary_data_from_db.get("summary", {}),
            overall_risk_score=summary_data_from_db.get("overall_risk_score", {}),
            # This is a bit of a hack for PDF generation, we don't need the files here
            files_analyzed=[],
        )

        # Generate the HTML and then the PDF
        html_content = create_executive_summary_html(
            impact_report_model, summary_report_model
        )
        pdf_bytes = generate_pdf_from_html(html_content)

        logger.info(f"Successfully generated PDF for scan {scan_id}.")
        return pdf_bytes
