"""Smoke test that the new ``Finding.source`` column survives a
``save_findings`` insert and reads back correctly.

The prescan node returns ``VulnerabilityFinding(source="bandit", ...)``
and the existing ``ScanRepository.save_findings`` bulk-inserts via
``model_dump()``. Without the column on the ORM model the dict round-
trip would silently drop the field on insert; this test pins the
contract.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_repo import ScanRepository


@pytest.mark.asyncio
async def test_save_findings_persists_source_field(db_session, seeded_user):
    project = db_models.Project(user_id=seeded_user.id, name="src-test")
    db_session.add(project)
    await db_session.flush()

    scan = db_models.Scan(
        id=uuid.uuid4(),
        project_id=project.id,
        user_id=seeded_user.id,
        scan_type="AUDIT",
        status="COMPLETED",
        frameworks=["asvs"],
    )
    db_session.add(scan)
    await db_session.flush()

    finding = VulnerabilityFinding(
        cwe="CWE-78",
        title="Bandit B602",
        description="subprocess shell=True",
        severity="High",
        line_number=3,
        remediation="Use shell=False with a list of arguments.",
        confidence="High",
        references=[],
        cvss_score=None,
        cvss_vector=None,
        file_path="vuln.py",
        fixes=None,
        source="bandit",
        agent_name=None,
        corroborating_agents=None,
        is_applied_in_remediation=False,
    )

    repo = ScanRepository(db_session)
    await repo.save_findings(scan.id, [finding])
    await db_session.flush()

    rows = (
        (
            await db_session.execute(
                select(db_models.Finding).where(db_models.Finding.scan_id == scan.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].source == "bandit"
    assert rows[0].cwe == "CWE-78"
    assert rows[0].confidence == "High"
