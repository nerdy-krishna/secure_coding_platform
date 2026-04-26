"""Scan-lifecycle service: post-creation state transitions.

Handles the prescan-approval gate, cost-approval gate, cancellation,
and the two apply-fixes paths (full + selective).

Split out of `core/services/scan_service.py` (2026-04-26). Method
bodies are verbatim copies — no logic change. The threat-model
mitigations carry through unchanged: kind-vs-status guard +
PRESCAN_OVERRIDE_CRITICAL_SECRET / PRESCAN_USER_DECLINED audit
ScanEvent writes (M4 / G-split-5).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, List, Optional

from fastapi import HTTPException, status

from app.api.v1 import models as api_models
from app.config.config import settings
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_outbox_repo import (
    ScanOutboxRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.messaging.publisher import publish_message
from app.shared.lib.files import get_language_from_filename
from app.shared.lib.scan_status import (
    ACTIVE_SCAN_STATUSES,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_PENDING_APPROVAL,
    STATUS_PENDING_PRESCAN_APPROVAL,
    STATUS_QUEUED_FOR_SCAN,
    STATUS_REMEDIATION_COMPLETED,
)

logger = logging.getLogger(__name__)


class ScanLifecycleService:
    """Post-creation scan transitions.

    Same `__init__` shape as `ScanSubmissionService` — both build the
    outbox repo from the SAME `repo.db` session so `approve_scan`'s
    Scan + ScanEvent + Outbox writes stay atomic (G-split-2).
    """

    def __init__(self, repo: ScanRepository):
        self.repo = repo
        self.outbox = ScanOutboxRepository(repo.db)

    async def _get_scan_or_404(self, scan_id: uuid.UUID) -> db_models.Scan:
        """Internal helper. Mirrors the legacy `get_scan_status` shape
        without pulling the full query service in. Raises 404 if the
        scan doesn't exist."""
        scan = await self.repo.get_scan(scan_id)
        if not scan:
            logger.warning("Scan not found.", extra={"scan_id": str(scan_id)})
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan

    async def approve_scan(
        self,
        scan_id: uuid.UUID,
        user: db_models.User,
        request: Optional[Any] = None,
    ) -> None:
        """Approve / decline a scan paused at a worker-graph interrupt.

        Two interrupt points (ADR-009): prescan-approval and cost-
        approval. ``request.kind`` discriminates; the consumer
        re-validates kind against the scan's pause point before
        invoking LangGraph (defense in depth).

        For prescan-approval with ``approved=True`` and
        ``override_critical_secret=True`` AND any Critical Gitleaks
        finding present, this method writes a
        ``PRESCAN_OVERRIDE_CRITICAL_SECRET`` scan_event so the
        decision is auditable (M10).
        """
        # Late import to avoid circulars (api.v1.models imports schemas
        # that pull this module transitively).
        from app.api.v1.models import ApprovalRequest

        if request is None:
            request = ApprovalRequest()

        logger.info(
            "Attempting to approve scan.",
            extra={
                "scan_id": str(scan_id),
                "user_id": user.id,
                "kind": request.kind,
                "approved": request.approved,
            },
        )
        scan = await self._get_scan_or_404(scan_id)
        if scan.user_id != user.id and not user.is_superuser:
            raise HTTPException(
                status_code=403, detail="Not authorized to approve this scan"
            )

        # Validate kind against current pause point. Keeps a
        # `kind="cost_approval"` payload from accidentally (or
        # adversarially) advancing past a `PENDING_PRESCAN_APPROVAL`
        # gate. (M1 / G4 — also re-checked in the worker consumer.)
        if request.kind == "prescan_approval":
            if scan.status != STATUS_PENDING_PRESCAN_APPROVAL:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Approval kind 'prescan_approval' requires status "
                        f"PENDING_PRESCAN_APPROVAL; current status: {scan.status}"
                    ),
                )
        elif request.kind == "cost_approval":
            if scan.status != STATUS_PENDING_APPROVAL:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Approval kind 'cost_approval' requires status "
                        f"PENDING_COST_APPROVAL; current status: {scan.status}"
                    ),
                )

        # Audit trail for the override path (M10): if the operator is
        # honoring an override on a Critical Gitleaks finding, persist
        # a scan_event so the decision is auditable.
        if (
            request.kind == "prescan_approval"
            and request.approved
            and request.override_critical_secret
        ):
            await self.repo.create_scan_event(
                scan_id=scan_id,
                stage_name="PRESCAN_OVERRIDE_CRITICAL_SECRET",
                status="COMPLETED",
            )

        # Audit trail for the decline path: operator chose Stop on the
        # prescan card. The worker then routes to `user_decline_node`
        # which sets STATUS_BLOCKED_USER_DECLINE.
        if request.kind == "prescan_approval" and not request.approved:
            await self.repo.create_scan_event(
                scan_id=scan_id,
                stage_name="PRESCAN_USER_DECLINED",
                status="COMPLETED",
            )

        # For cost_approval and prescan_approval-approve, the next
        # worker phase actually progresses so transitioning to
        # QUEUED_FOR_SCAN is a reasonable intermediate. For
        # prescan_approval-decline, leave the status as
        # PENDING_PRESCAN_APPROVAL — the worker's user_decline_node
        # will set BLOCKED_USER_DECLINE within milliseconds of resume.
        if not (request.kind == "prescan_approval" and not request.approved):
            await self.repo.update_status(scan_id, STATUS_QUEUED_FOR_SCAN)
            await self.repo.create_scan_event(
                scan_id=scan_id, stage_name="QUEUED_FOR_SCAN", status="COMPLETED"
            )
        approval_payload = {
            "scan_id": str(scan_id),
            "action": "resume_analysis",
            "kind": request.kind,
            "approved": request.approved,
            "override_critical_secret": request.override_critical_secret,
        }
        outbox_row = await self.outbox.enqueue(
            scan_id=scan_id,
            queue_name=settings.RABBITMQ_APPROVAL_QUEUE,
            payload=approval_payload,
        )
        published = await publish_message(
            settings.RABBITMQ_APPROVAL_QUEUE,
            approval_payload,
        )
        if published:
            await self.outbox.mark_published(outbox_row.id)
            logger.info(
                "Scan approved and queued for processing.",
                extra={"scan_id": str(scan_id), "kind": request.kind},
            )
        else:
            await self.outbox.record_failed_attempt(outbox_row.id)
            logger.warning(
                "Approval enqueued to outbox but RabbitMQ publish failed; "
                "sweeper will retry.",
                extra={"scan_id": str(scan_id)},
            )

    async def get_prescan_review(
        self, scan_id: uuid.UUID, user: db_models.User
    ) -> "api_models.PrescanReviewResponse":
        """Findings + override-flag for the prescan-approval card (G6).

        Allowed only when the scan is at the prescan-approval gate or
        already in one of the two terminal blocked states (so the user
        can audit the post-decision state on the same screen). Other
        statuses 400.
        """
        from app.api.v1 import models as api_models  # local import — avoid circ
        from app.shared.lib.scan_status import (
            STATUS_BLOCKED_PRE_LLM,
            STATUS_BLOCKED_USER_DECLINE,
        )

        scan = await self.repo.get_scan(scan_id)
        if not scan or (scan.user_id != user.id and not user.is_superuser):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        review_statuses = {
            STATUS_PENDING_PRESCAN_APPROVAL,
            STATUS_BLOCKED_PRE_LLM,
            STATUS_BLOCKED_USER_DECLINE,
        }
        if scan.status not in review_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Prescan review only available while scan is at "
                    "PENDING_PRESCAN_APPROVAL or in a prescan-blocked "
                    f"state; current status: {scan.status}"
                ),
            )

        rows = await self.repo.get_findings_for_scan(scan_id)
        items = [api_models.PrescanFindingItem.model_validate(r) for r in rows]
        has_critical_secret = any(
            (r.source == "gitleaks") and (r.severity == "Critical") for r in rows
        )
        return api_models.PrescanReviewResponse(
            scan_id=scan_id,
            status=scan.status,
            findings=items,
            has_critical_secret=has_critical_secret,
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

        if scan.status not in ACTIVE_SCAN_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan cannot be cancelled from its current state: {scan.status}",
            )

        await self.repo.update_status(scan_id, STATUS_CANCELLED)
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

        if scan.scan_type != "AUDIT_AND_REMEDIATE" or scan.status != STATUS_COMPLETED:
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
        await self.repo.update_status(scan_id, STATUS_REMEDIATION_COMPLETED)
        logger.info(
            f"All fixes applied for scan {scan_id}. Status set to REMEDIATION_COMPLETED."
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
        await self.repo.update_status(scan_id, STATUS_REMEDIATION_COMPLETED)
        logger.info(
            f"Selective fixes applied for scan {scan_id}. Status set to REMEDIATION_COMPLETED."
        )
