# src/app/core/services/compliance_service.py
"""Compliance aggregation service.

Rolls up per-framework stats for the Compliance page:
- doc_count comes from the RAG collection (reuse rag_service.get_framework_stats).
- findings_matched comes from Finding rows whose parent Scan was run with
  that framework selected (Scan.frameworks JSONB array).
- open_findings is the same set, filtered to unresolved severities.
- score is a simple heuristic (100 - clamp(open * 2)). Explicitly server-side
  so we remove the literal placeholder on the UI.

The service always returns the three default frameworks (asvs,
proactive_controls, cheatsheets) even when no documents are ingested;
custom frameworks from the `frameworks` table follow.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.infrastructure.rag.rag_client import RAGService

logger = logging.getLogger(__name__)


# Defaults always shown on the Compliance page, even when not installed.
# Display names and ingestion modes mirror what the RAG admin page accepts.
DEFAULT_FRAMEWORKS: Dict[str, Dict[str, str]] = {
    "asvs": {
        "display_name": "OWASP ASVS",
        "description": "Application Security Verification Standard. Best for comprehensive auditing.",
        "ingest_mode": "csv",
    },
    "proactive_controls": {
        "display_name": "OWASP Proactive Controls",
        "description": "Developer-focused controls (C1-C10). Great for chat context.",
        "ingest_mode": "git_url",
    },
    "cheatsheets": {
        "display_name": "OWASP Cheatsheets",
        "description": "Topic-specific security cheatsheets.",
        "ingest_mode": "git_url",
    },
}

# Severity buckets considered "open". Informational is tracked separately.
_OPEN_SEVERITIES = {"critical", "high", "medium", "low"}


@dataclass
class FrameworkStats:
    name: str
    display_name: str
    description: str
    framework_type: str  # "default" | "custom"
    ingest_mode: Optional[str]  # "csv" | "git_url" | None (custom)
    is_installed: bool
    doc_count: int
    findings_matched: int
    open_findings: int
    score: int
    last_scanned_at: Optional[datetime]

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "framework_type": self.framework_type,
            "ingest_mode": self.ingest_mode,
            "is_installed": self.is_installed,
            "doc_count": self.doc_count,
            "findings_matched": self.findings_matched,
            "open_findings": self.open_findings,
            "score": self.score,
            "last_scanned_at": (
                self.last_scanned_at.isoformat() if self.last_scanned_at else None
            ),
        }


def _score_from_open(open_count: int) -> int:
    """Heuristic: start at 100, subtract 2 per open finding, clamp at 5.

    Explicit and documented so the UI can surface it without pretending a
    richer model exists. Real scoring lives in a dedicated service once
    Finding→Control mapping is in place.
    """
    return max(5, 100 - min(95, open_count * 2))


class ComplianceService:
    def __init__(self, db: AsyncSession, rag_service: Optional[RAGService]):
        self.db = db
        self.rag_service = rag_service

    async def get_stats(
        self, visible_user_ids: Optional[List[int]]
    ) -> List[Dict[str, object]]:
        """Return per-framework stats.

        `visible_user_ids=None` means no user filter (admin view). An empty
        list returns zeros everywhere — reflects a user with no scans.
        """
        # 1. Doc counts per default framework from RAG.
        doc_counts: Dict[str, int] = {
            "asvs": 0,
            "proactive_controls": 0,
            "cheatsheets": 0,
        }
        if self.rag_service:
            try:
                doc_counts.update(self.rag_service.get_framework_stats())
            except Exception as e:
                logger.warning("RAG doc-count lookup failed: %s", e)

        # 2. Findings aggregates per framework in scope.
        matched, open_counts, last_seen = await self._aggregate_findings(
            visible_user_ids
        )

        # 3. Custom frameworks from DB.
        custom_rows = await self._list_custom_frameworks()

        out: List[FrameworkStats] = []
        for name, meta in DEFAULT_FRAMEWORKS.items():
            doc_count = doc_counts.get(name, 0)
            out.append(
                FrameworkStats(
                    name=name,
                    display_name=meta["display_name"],
                    description=meta["description"],
                    framework_type="default",
                    ingest_mode=meta["ingest_mode"],
                    is_installed=doc_count > 0,
                    doc_count=doc_count,
                    findings_matched=matched.get(name, 0),
                    open_findings=open_counts.get(name, 0),
                    score=_score_from_open(open_counts.get(name, 0)),
                    last_scanned_at=last_seen.get(name),
                )
            )

        for fw in custom_rows:
            out.append(
                FrameworkStats(
                    name=fw.name,
                    display_name=fw.name,
                    description=fw.description or "",
                    framework_type="custom",
                    ingest_mode=None,
                    is_installed=True,  # custom = already in the DB
                    doc_count=0,
                    findings_matched=matched.get(fw.name, 0),
                    open_findings=open_counts.get(fw.name, 0),
                    score=_score_from_open(open_counts.get(fw.name, 0)),
                    last_scanned_at=last_seen.get(fw.name),
                )
            )

        return [item.to_dict() for item in out]

    async def _aggregate_findings(
        self, visible_user_ids: Optional[List[int]]
    ) -> tuple[Dict[str, int], Dict[str, int], Dict[str, datetime]]:
        """Join Finding→Scan and bucket by every framework in Scan.frameworks.

        Returns (matched_per_fw, open_per_fw, last_seen_per_fw).
        Postgres jsonb_array_elements_text is the cleanest way to explode
        the JSONB array; we filter & group in Python after pulling a narrow
        projection. This stays fast for reasonable finding volumes and
        avoids a complex SQLAlchemy construct for a first cut.
        """
        stmt = select(
            db_models.Scan.frameworks,
            db_models.Scan.created_at,
            db_models.Finding.severity,
        ).join(db_models.Finding, db_models.Finding.scan_id == db_models.Scan.id)
        if visible_user_ids is not None:
            stmt = stmt.where(db_models.Scan.user_id.in_(visible_user_ids))

        result = await self.db.execute(stmt)
        matched: Dict[str, int] = {}
        open_counts: Dict[str, int] = {}
        last_seen: Dict[str, datetime] = {}

        for frameworks, created_at, severity in result.all():
            if not frameworks:
                continue
            sev_lower = (severity or "").lower()
            is_open = sev_lower in _OPEN_SEVERITIES
            for fw in frameworks:
                matched[fw] = matched.get(fw, 0) + 1
                if is_open:
                    open_counts[fw] = open_counts.get(fw, 0) + 1
                prior = last_seen.get(fw)
                if created_at and (prior is None or created_at > prior):
                    last_seen[fw] = created_at
        return matched, open_counts, last_seen

    async def _list_custom_frameworks(self) -> List[db_models.Framework]:
        default_names = set(DEFAULT_FRAMEWORKS.keys())
        stmt = select(db_models.Framework).where(
            ~db_models.Framework.name.in_(default_names)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_controls(self, framework_name: str) -> List[Dict[str, object]]:
        """Return RAG documents for a framework, grouped by control ID.

        ASVS ingestion stores `control_id` on the metadata; Proactive Controls
        / Cheatsheets use section-level titles instead. This method pulls
        whatever is in ChromaDB for the framework and groups by the first
        available identifier key, falling back to a single "overview" bucket.
        """
        if not self.rag_service:
            return []
        try:
            result = self.rag_service.get_by_framework(framework_name)
        except Exception as e:
            logger.warning("RAG get_by_framework failed: %s", e)
            return []

        documents = result.get("documents", []) or []
        metadatas = result.get("metadatas", []) or []

        buckets: Dict[str, Dict[str, object]] = {}
        for doc, meta in zip(documents, metadatas):
            meta = meta or {}
            control_id = (
                meta.get("control_id")
                or meta.get("section")
                or meta.get("title")
                or "overview"
            )
            bucket = buckets.setdefault(
                str(control_id),
                {
                    "control_id": str(control_id),
                    "title": meta.get("title")
                    or meta.get("section")
                    or str(control_id),
                    "count": 0,
                    "sample": None,
                },
            )
            bucket["count"] = int(bucket["count"]) + 1  # type: ignore[arg-type]
            if not bucket["sample"] and isinstance(doc, str):
                bucket["sample"] = doc[:240]

        return sorted(buckets.values(), key=lambda b: b["control_id"])  # type: ignore[arg-type]


def get_compliance_service(
    db: AsyncSession,
    rag_service: Optional[RAGService],
) -> ComplianceService:
    return ComplianceService(db=db, rag_service=rag_service)
