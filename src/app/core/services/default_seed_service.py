# src/app/core/services/default_seed_service.py
"""Idempotent seeder for the default frameworks, agents, and prompt templates.

Single source of truth for what the platform ships with out of the box.
Called from three places:

- Application startup (auto-seed on empty DB) — see lifespan hook in main.py.
- Admin endpoint `POST /api/v1/admin/seed/defaults` for manual re-seed.
- CLI wrapper `scripts/populate_agents_and_frameworks.py`.

`seed_defaults(session, force_reset=False)` only inserts rows that are
missing. When `force_reset=True`, the same cleanup the original script
performed runs first (delete legacy framework names, then re-insert).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.agent_repo import AgentRepository
from app.infrastructure.database.repositories.framework_repo import (
    FrameworkRepository,
)
from app.infrastructure.database.repositories.prompt_template_repo import (
    PromptTemplateRepository,
)

logger = logging.getLogger(__name__)


# --- Data ---------------------------------------------------------------------

FRAMEWORKS_DATA: List[Dict[str, str]] = [
    {
        "name": "asvs",
        "description": (
            "The OWASP Application Security Verification Standard (ASVS) is a "
            "standard for performing application security verifications."
        ),
    },
    {
        "name": "proactive_controls",
        "description": "OWASP Proactive Controls for Developers.",
    },
    {
        "name": "cheatsheets",
        "description": "OWASP Cheatsheets Series.",
    },
]


AGENT_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "AccessControlAgent",
        "description": (
            "Analyzes for vulnerabilities related to user permissions, "
            "authorization, and insecure direct object references."
        ),
        "domain_query": {
            "keywords": (
                "access control, authorization, user permissions, roles, "
                "insecure direct object reference (IDOR), privileges, broken "
                "object level authorization, function level authorization"
            ),
            "metadata_filter": {"control_family": ["Authorization"]},
        },
    },
    {
        "name": "ApiSecurityAgent",
        "description": (
            "Focuses on the security of API endpoints, including REST, GraphQL, "
            "and other web services."
        ),
        "domain_query": {
            "keywords": (
                "API security, REST, GraphQL, API keys, rate limiting, API "
                "authentication, API authorization, endpoint security, JWT, "
                "OAuth, mass assignment"
            ),
            "metadata_filter": {
                "control_family": ["API and Web Service", "OAuth and OIDC"]
            },
        },
    },
    {
        "name": "ArchitectureAgent",
        "description": (
            "Assesses the overall security architecture, design patterns, "
            "and data flow."
        ),
        "domain_query": {
            "keywords": (
                "security architecture, design patterns, data flow, trust "
                "boundaries, tiering, segregation, component separation, "
                "security principles, microservices security"
            ),
            "metadata_filter": {"control_family": ["Secure Coding and Architecture"]},
        },
    },
    {
        "name": "AuthenticationAgent",
        "description": (
            "Scrutinizes login mechanisms, password policies, multi-factor "
            "authentication, and credential management."
        ),
        "domain_query": {
            "keywords": (
                "authentication, login, password policies, credential "
                "management, multi-factor authentication (MFA), single "
                "sign-on (SSO), password hashing, forgot password, "
                "remember me"
            ),
            "metadata_filter": {"control_family": ["Authentication"]},
        },
    },
    {
        "name": "BusinessLogicAgent",
        "description": (
            "Looks for flaws in the application's business logic that could "
            "be exploited."
        ),
        "domain_query": {
            "keywords": (
                "business logic vulnerabilities, workflow abuse, race "
                "conditions, unexpected application state, feature misuse, "
                "price manipulation, excessive computation"
            ),
            "metadata_filter": {"control_family": ["Validation and Business Logic"]},
        },
    },
    {
        "name": "CodeIntegrityAgent",
        "description": (
            "Verifies the integrity of code and dependencies to prevent " "tampering."
        ),
        "domain_query": {
            "keywords": (
                "software integrity, code signing, dependency security, "
                "supply chain attacks, insecure deserialization, code "
                "tampering, third-party libraries, SCA, software composition "
                "analysis"
            ),
            "metadata_filter": {"control_family": ["Secure Coding and Architecture"]},
        },
    },
    {
        "name": "CommunicationAgent",
        "description": (
            "Checks for secure data transmission, use of TLS, and protection "
            "against network-level attacks."
        ),
        "domain_query": {
            "keywords": (
                "secure communication, TLS, SSL, HTTPS, certificate "
                "validation, weak ciphers, transport layer security, data in "
                "transit, network security protocols"
            ),
            "metadata_filter": {"control_family": ["Secure Communication"]},
        },
    },
    {
        "name": "ConfigurationAgent",
        "description": (
            "Inspects for misconfigurations in the application, server, or "
            "third-party services."
        ),
        "domain_query": {
            "keywords": (
                "security misconfiguration, default credentials, verbose "
                "error messages, unnecessary features, improper server "
                "hardening, security headers, file permissions"
            ),
            "metadata_filter": {"control_family": ["Configuration"]},
        },
    },
    {
        "name": "CryptographyAgent",
        "description": (
            "Evaluates the use of encryption, hashing algorithms, and "
            "key management."
        ),
        "domain_query": {
            "keywords": (
                "cryptography, encryption, hashing algorithms, weak ciphers, "
                "key management, PRNG, random number generation, IV, "
                "initialization vector, broken cryptography"
            ),
            "metadata_filter": {"control_family": ["Cryptography"]},
        },
    },
    {
        "name": "DataProtectionAgent",
        "description": (
            "Focuses on the protection of sensitive data at rest and in "
            "transit, including PII."
        ),
        "domain_query": {
            "keywords": (
                "data protection, sensitive data exposure, PII, personally "
                "identifiable information, data at rest, data classification, "
                "data masking, tokenization, GDPR, CCPA"
            ),
            "metadata_filter": {"control_family": ["Data Protection"]},
        },
    },
    {
        "name": "ErrorHandlingAgent",
        "description": (
            "Analyzes error handling routines to prevent information leakage."
        ),
        "domain_query": {
            "keywords": (
                "error handling, information leakage, stack traces, verbose "
                "error messages, debugging information exposure, exception "
                "handling, logging sensitive information"
            ),
            "metadata_filter": {
                "control_family": ["Security Logging and Error Handling"]
            },
        },
    },
    {
        "name": "FileHandlingAgent",
        "description": (
            "Scrutinizes file upload, download, and processing functionality "
            "for vulnerabilities."
        ),
        "domain_query": {
            "keywords": (
                "file handling, file upload vulnerabilities, path traversal, "
                "directory traversal, unrestricted file upload, malware "
                "upload, remote file inclusion (RFI), local file inclusion "
                "(LFI)"
            ),
            "metadata_filter": {"control_family": ["File Handling"]},
        },
    },
    {
        "name": "SessionManagementAgent",
        "description": (
            "Checks for secure session handling, token management, and "
            "protection against session hijacking."
        ),
        "domain_query": {
            "keywords": (
                "session management, session fixation, session hijacking, "
                "cookie security, insecure session tokens, session timeout, "
                "CSRF, cross-site request forgery, JWT session tokens"
            ),
            "metadata_filter": {"control_family": ["Session Management"]},
        },
    },
    {
        "name": "ValidationAgent",
        "description": (
            "Focuses on input validation, output encoding, and prevention of "
            "injection attacks like SQLi and XSS."
        ),
        "domain_query": {
            "keywords": (
                "input validation, output encoding, SQL injection (SQLi), "
                "Cross-Site Scripting (XSS), command injection, type "
                "validation, sanitization, denylisting, allowlisting, "
                "parameter tampering"
            ),
            "metadata_filter": {
                "control_family": [
                    "Encoding and Sanitization",
                    "Validation and Business Logic",
                ]
            },
        },
    },
    {
        "name": "BuildDeploymentAgent",
        "description": (
            "Ensures security in the build and deployment pipeline, including "
            "CI/CD security and reproducible builds."
        ),
        "domain_query": {
            "keywords": (
                "build security, deployment security, CI/CD, pipeline "
                "security, reproducible builds, software bill of materials, "
                "SBOM, artifact integrity, git security"
            ),
            "metadata_filter": {"control_family": ["Build and Deployment"]},
        },
    },
    {
        "name": "ClientSideAgent",
        "description": (
            "Analyzes client-side security risks, including DOM XSS, WebRTC, "
            "and modern frontend framework vulnerabilities."
        ),
        "domain_query": {
            "keywords": (
                "client-side security, DOM XSS, WebRTC, frontend security, "
                "CORS, CSP, subresource integrity, javascript security, "
                "browser security"
            ),
            "metadata_filter": {"control_family": ["Client Side"]},
        },
    },
    {
        "name": "CloudContainerAgent",
        "description": (
            "Focuses on cloud-native security, container hardening, and "
            "orchestration security."
        ),
        "domain_query": {
            "keywords": (
                "cloud security, container security, docker security, "
                "kubernetes, orchestration, cloud misconfiguration, "
                "serverless security, cloud storage, IAM roles"
            ),
            "metadata_filter": {"control_family": ["Cloud and Container"]},
        },
    },
]


# Prompt templates are generated programmatically from the agent list so the
# per-agent audit/remediation variants stay in sync with the agent roster.
_AUDIT_TEMPLATE = """You are an expert security auditor. Your task is to audit the provided code for vulnerabilities based on the given patterns.

<CONTEXT_EXPLANATION>
The <VULNERABILITY_PATTERNS> section below contains specific security requirements and anti-patterns retrieved from the knowledge base.
Each pattern may include:
- **Description**: The core security requirement.
- **Vulnerable Code Example**: A snippet showing insecure implementation (Anti-Pattern).
- **Secure Code Example**: A snippet showing the correct implementation (Reference).

Use these patterns to identify similar vulnerable logic in the <CODE_BUNDLE>.
</CONTEXT_EXPLANATION>

1.  Analyze the `<CODE_BUNDLE>` below.
2.  Compare the code against the `<VULNERABILITY_PATTERNS>`.
3.  For each vulnerability you find, provide a detailed finding. This MUST include:
    - A concise 'title'.
    - A 'description' of the root cause, referencing the specific pattern matched.
    - 'severity' and 'confidence' ratings.
    - The 'line_number' where the vulnerability occurs.
    - A full CVSS 3.1 'cvss_vector' string (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').
    - A detailed 'remediation' guide.
    - A list of technical 'keywords' that characterize the vulnerability.
4.  Do NOT suggest any code fixes in this step.

<VULNERABILITY_PATTERNS>
{vulnerability_patterns}
</VULNERABILITY_PATTERNS>

<REFERENCE_SECURE_PATTERNS>
{secure_patterns}
</REFERENCE_SECURE_PATTERNS>

<CODE_BUNDLE>
{code_bundle}
</CODE_BUNDLE>

Respond ONLY with a valid JSON object that conforms to the InitialAnalysisResponse schema, containing a list of findings.
"""


_REMEDIATION_TEMPLATE = """You are an expert security engineer. Your task is to find and fix vulnerabilities in the provided code.

<CONTEXT_EXPLANATION>
The data below is retrieved from the specialized security knowledge base:
- <VULNERABILITY_PATTERNS>: Contains descriptions and examples of insecure code (Anti-Patterns).
- <SECURE_PATTERNS>: Contains vetted, secure code examples (Positive Patterns) that demonstrate the correct implementation.
</CONTEXT_EXPLANATION>

1.  Analyze the `<CODE_BUNDLE>` below.
2.  Identify vulnerabilities using the `<VULNERABILITY_PATTERNS>`.
3.  **CRITICAL**: When generating the fix, you MUST follow the patterns in `<SECURE_PATTERNS>`.
    - If a specific secure code example is provided for the vulnerability, adapt it to the context of the code bundle.
    - Ensure your fix addresses the root cause described in the Anti-Pattern.
4.  For each vulnerability you find, provide a detailed finding AND a suggested code fix. The finding MUST include:
    - A concise 'title'.
    - A 'description' of the root cause.
    - 'severity' and 'confidence' ratings.
    - The 'line_number' where the vulnerability occurs.
    - A full CVSS 3.1 'cvss_vector' string.
    - A detailed 'remediation' guide.
    - A list of technical 'keywords'.
    - A 'fix' object containing the exact 'original_snippet' to be replaced and the new 'code'.
5.  The `code` in your `fix` object must be a **surgical, drop-in replacement** for the `original_snippet`. It must ONLY contain the specific lines of code that are changing.

<VULNERABILITY_PATTERNS>
{vulnerability_patterns}
</VULNERABILITY_PATTERNS>

<SECURE_PATTERNS>
{secure_patterns}
</SECURE_PATTERNS>

<CODE_BUNDLE>
{code_bundle}
</CODE_BUNDLE>

Respond ONLY with a valid JSON object that conforms to the InitialAnalysisResponse schema, containing a list of findings with their associated fixes.
"""


_CHAT_TEMPLATE = """You are an expert AI Security Advisor. Your role is to provide clear, accurate, and helpful advice on software security.

<CONTEXT_EXPLANATION>
You have access to a specialized security knowledge base.
The user has enabled the following security frameworks for this session:
{framework_context}
</CONTEXT_EXPLANATION>

<INSTRUCTIONS>
1.  **Analyze the User's Question**.
2.  **Review the <SECURITY_CONTEXT_FROM_KNOWLEDGE_BASE>**. This section contains retrieved documents relevant to the question.
    - If you find relevant information in the context, **cite the source** (e.g., "According to the OWASP Cheatsheet on X...", "ASVS Requirement 5.1.2 states...").
    - Prioritize this context over general knowledge.
3.  **Look for Code Patterns**: The context may contain `[[LANGUAGE PATTERNS]]` with `Vulnerable` and `Secure` examples.
    - If the user asks for code examples, prefer using these vetted patterns.
4.  **Be Practical**: Provide actionable advice. If the context suggests a specific library or approach, recommend it.
5.  **Fallback**: If the context is empty or irrelevant, rely on your general expert knowledge but mention that you are doing so.
</INSTRUCTIONS>

<CONVERSATION_HISTORY>
{history_str}
</CONVERSATION_HISTORY>

<SECURITY_CONTEXT_FROM_KNOWLEDGE_BASE>
{rag_context}
</SECURITY_CONTEXT_FROM_KNOWLEDGE_BASE>

Current User Question: "{user_question}"

Respond ONLY with a valid JSON object conforming to the ChatResponse schema.
"""


def _build_prompt_templates() -> List[Dict[str, Any]]:
    templates: List[Dict[str, Any]] = []
    for agent in AGENT_DEFINITIONS:
        templates.append(
            {
                "name": f"{agent['name']} - Quick Audit",
                "template_type": "QUICK_AUDIT",
                "agent_name": agent["name"],
                "version": 2,
                "template_text": _AUDIT_TEMPLATE,
            }
        )
        templates.append(
            {
                "name": f"{agent['name']} - Detailed Remediation",
                "template_type": "DETAILED_REMEDIATION",
                "agent_name": agent["name"],
                "version": 2,
                "template_text": _REMEDIATION_TEMPLATE,
            }
        )
    templates.append(
        {
            "name": "SecurityAdvisorPrompt",
            "template_type": "CHAT",
            "agent_name": "SecurityAdvisorAgent",
            "version": 2,
            "template_text": _CHAT_TEMPLATE,
        }
    )
    return templates


PROMPT_TEMPLATES: List[Dict[str, Any]] = _build_prompt_templates()


# Legacy framework display names cleaned up by force_reset.
_LEGACY_FRAMEWORK_NAMES = [
    "OWASP ASVS",
    "OWASP ASVS v5.0",
    "OWASP Cheatsheets",
    "OWASP Proactive Controls",
]


@dataclass
class SeedResult:
    frameworks_added: int
    agents_added: int
    templates_added: int
    mappings_refreshed: int
    reset: bool

    def as_dict(self) -> Dict[str, Any]:
        return {
            "frameworks_added": self.frameworks_added,
            "agents_added": self.agents_added,
            "templates_added": self.templates_added,
            "mappings_refreshed": self.mappings_refreshed,
            "reset": self.reset,
        }


async def seed_defaults(
    session: AsyncSession,
    *,
    force_reset: bool = False,
) -> SeedResult:
    """Ensure default frameworks, agents, and prompt templates exist.

    When `force_reset=True`, delete the managed rows first — matches the
    old CLI script's behavior. When False (the default), only insert
    missing rows; existing customisations stay intact.
    """
    framework_repo = FrameworkRepository(session)
    agent_repo = AgentRepository(session)
    prompt_repo = PromptTemplateRepository(session)

    target_fw_names = [fw["name"] for fw in FRAMEWORKS_DATA]
    target_agent_names = [a["name"] for a in AGENT_DEFINITIONS] + [
        "SecurityAdvisorAgent"
    ]

    if force_reset:
        logger.info("Seeding defaults with force_reset=True; clearing managed rows.")

        # 1. Clear framework-agent mappings for any target/legacy framework.
        frameworks_to_clear = await session.execute(
            select(db_models.Framework)
            .options(selectinload(db_models.Framework.agents))
            .where(
                db_models.Framework.name.in_(target_fw_names + _LEGACY_FRAMEWORK_NAMES)
            )
        )
        for fw in frameworks_to_clear.scalars().all():
            fw.agents = []
        await session.commit()

        # 2. Drop prompt templates + agents + frameworks managed here.
        await session.execute(
            delete(db_models.PromptTemplate).where(
                db_models.PromptTemplate.agent_name.in_(target_agent_names)
            )
        )
        await session.execute(
            delete(db_models.Agent).where(db_models.Agent.name.in_(target_agent_names))
        )
        await session.execute(
            delete(db_models.Framework).where(
                db_models.Framework.name.in_(target_fw_names + _LEGACY_FRAMEWORK_NAMES)
            )
        )
        await session.commit()

    # Existing-name lookup so we only insert missing rows.
    existing_fws = await session.execute(
        select(db_models.Framework.name).where(
            db_models.Framework.name.in_(target_fw_names)
        )
    )
    existing_fw_names = {row[0] for row in existing_fws.all()}

    existing_agents = await session.execute(
        select(db_models.Agent.name).where(db_models.Agent.name.in_(target_agent_names))
    )
    existing_agent_names = {row[0] for row in existing_agents.all()}

    existing_tpls = await session.execute(
        select(db_models.PromptTemplate.name).where(
            db_models.PromptTemplate.name.in_([tpl["name"] for tpl in PROMPT_TEMPLATES])
        )
    )
    existing_tpl_names = {row[0] for row in existing_tpls.all()}

    frameworks_added = 0
    for fw_def in FRAMEWORKS_DATA:
        if fw_def["name"] in existing_fw_names:
            continue
        await framework_repo.create_framework(api_models.FrameworkCreate(**fw_def))
        frameworks_added += 1

    agents_added = 0
    for agent_def in AGENT_DEFINITIONS:
        if agent_def["name"] in existing_agent_names:
            continue
        await agent_repo.create_agent(api_models.AgentCreate(**agent_def))
        agents_added += 1

    templates_added = 0
    for tpl_def in PROMPT_TEMPLATES:
        if tpl_def["name"] in existing_tpl_names:
            continue
        await prompt_repo.create_template(api_models.PromptTemplateCreate(**tpl_def))
        templates_added += 1

    await session.commit()

    # Framework↔agent mapping refresh. Always re-applies — cheap and keeps
    # the default roster consistent after this seed runs (including when
    # force_reset wasn't needed).
    mappings_refreshed = 0
    fw_rows = await session.execute(
        select(db_models.Framework).where(db_models.Framework.name.in_(target_fw_names))
    )
    agent_id_rows = await session.execute(
        select(db_models.Agent.id).where(
            db_models.Agent.name.in_([a["name"] for a in AGENT_DEFINITIONS])
        )
    )
    agent_ids = [row[0] for row in agent_id_rows.all()]
    if agent_ids:
        for fw in fw_rows.scalars().all():
            await framework_repo.update_agent_mappings_for_framework(fw.id, agent_ids)
            mappings_refreshed += 1

    return SeedResult(
        frameworks_added=frameworks_added,
        agents_added=agents_added,
        templates_added=templates_added,
        mappings_refreshed=mappings_refreshed,
        reset=force_reset,
    )


async def seed_if_empty(session: AsyncSession) -> SeedResult:
    """Auto-seed on startup. Runs only when the platform has zero agents
    AND zero prompt templates — treats that as "fresh install." Having
    fewer than this is considered a user choice we shouldn't override.
    """
    agent_count_result = await session.execute(select(db_models.Agent.id).limit(1))
    template_count_result = await session.execute(
        select(db_models.PromptTemplate.id).limit(1)
    )
    has_agents = agent_count_result.first() is not None
    has_templates = template_count_result.first() is not None

    if has_agents and has_templates:
        logger.debug("Auto-seed skipped: agents and templates already present.")
        return SeedResult(0, 0, 0, 0, False)

    logger.info(
        "Auto-seeding defaults on empty DB "
        f"(has_agents={has_agents}, has_templates={has_templates})."
    )
    return await seed_defaults(session, force_reset=False)
