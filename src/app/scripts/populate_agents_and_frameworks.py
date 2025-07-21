# src/app/scripts/populate_agents_and_frameworks.py
import asyncio
import logging
from sqlalchemy import delete, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.config.config import settings
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.agent_repo import AgentRepository
from app.infrastructure.database.repositories.framework_repo import FrameworkRepository
from app.infrastructure.database.repositories.prompt_template_repo import PromptTemplateRepository
from app.api.v1 import models as api_models

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Data Definitions ---

FRAMEWORK_DATA = {
    "name": "OWASP ASVS v5.0",
    "description": "The OWASP Application Security Verification Standard (ASVS) v5.0 is a standard for performing application security verifications."
}

AGENT_DEFINITIONS = [
    {
        "name": "AccessControlAgent",
        "description": "Analyzes for vulnerabilities related to user permissions, authorization, and insecure direct object references.",
        "domain_query": {
            "keywords": "access control, authorization, user permissions, roles, insecure direct object reference (IDOR), privileges, broken object level authorization, function level authorization",
            "metadata_filter": {"control_family": ["Authorization"]}
        }
    },
    {
        "name": "ApiSecurityAgent",
        "description": "Focuses on the security of API endpoints, including REST, GraphQL, and other web services.",
        "domain_query": {
            "keywords": "API security, REST, GraphQL, API keys, rate limiting, API authentication, API authorization, endpoint security, JWT, OAuth, mass assignment",
            "metadata_filter": {"control_family": ["API and Web Service", "OAuth and OIDC"]}
        }
    },
    {
        "name": "ArchitectureAgent",
        "description": "Assesses the overall security architecture, design patterns, and data flow.",
        "domain_query": {
            "keywords": "security architecture, design patterns, data flow, trust boundaries, tiering, segregation, component separation, security principles, microservices security",
            "metadata_filter": {"control_family": ["Secure Coding and Architecture"]}
        }
    },
    {
        "name": "AuthenticationAgent",
        "description": "Scrutinizes login mechanisms, password policies, multi-factor authentication, and credential management.",
        "domain_query": {
            "keywords": "authentication, login, password policies, credential management, multi-factor authentication (MFA), single sign-on (SSO), password hashing, forgot password, remember me",
            "metadata_filter": {"control_family": ["Authentication"]}
        }
    },
    {
        "name": "BusinessLogicAgent",
        "description": "Looks for flaws in the application's business logic that could be exploited.",
        "domain_query": {
            "keywords": "business logic vulnerabilities, workflow abuse, race conditions, unexpected application state, feature misuse, price manipulation, excessive computation",
            "metadata_filter": {"control_family": ["Validation and Business Logic"]}
        }
    },
    {
        "name": "CodeIntegrityAgent",
        "description": "Verifies the integrity of code and dependencies to prevent tampering.",
        "domain_query": {
            "keywords": "software integrity, code signing, dependency security, supply chain attacks, insecure deserialization, code tampering, third-party libraries, SCA, software composition analysis",
            "metadata_filter": {"control_family": ["Secure Coding and Architecture"]}
        }
    },
    {
        "name": "CommunicationAgent",
        "description": "Checks for secure data transmission, use of TLS, and protection against network-level attacks.",
        "domain_query": {
            "keywords": "secure communication, TLS, SSL, HTTPS, certificate validation, weak ciphers, transport layer security, data in transit, network security protocols",
            "metadata_filter": {"control_family": ["Secure Communication"]}
        }
    },
    {
        "name": "ConfigurationAgent",
        "description": "Inspects for misconfigurations in the application, server, or third-party services.",
        "domain_query": {
            "keywords": "security misconfiguration, default credentials, verbose error messages, unnecessary features, improper server hardening, security headers, file permissions",
            "metadata_filter": {"control_family": ["Configuration"]}
        }
    },
    {
        "name": "CryptographyAgent",
        "description": "Evaluates the use of encryption, hashing algorithms, and key management.",
        "domain_query": {
            "keywords": "cryptography, encryption, hashing algorithms, weak ciphers, key management, PRNG, random number generation, IV, initialization vector, broken cryptography",
            "metadata_filter": {"control_family": ["Cryptography"]}
        }
    },
    {
        "name": "DataProtectionAgent",
        "description": "Focuses on the protection of sensitive data at rest and in transit, including PII.",
        "domain_query": {
            "keywords": "data protection, sensitive data exposure, PII, personally identifiable information, data at rest, data classification, data masking, tokenization, GDPR, CCPA",
            "metadata_filter": {"control_family": ["Data Protection"]}
        }
    },
    {
        "name": "ErrorHandlingAgent",
        "description": "Analyzes error handling routines to prevent information leakage.",
        "domain_query": {
            "keywords": "error handling, information leakage, stack traces, verbose error messages, debugging information exposure, exception handling, logging sensitive information",
            "metadata_filter": {"control_family": ["Security Logging and Error Handling"]}
        }
    },
    {
        "name": "FileHandlingAgent",
        "description": "Scrutinizes file upload, download, and processing functionality for vulnerabilities.",
        "domain_query": {
            "keywords": "file handling, file upload vulnerabilities, path traversal, directory traversal, unrestricted file upload, malware upload, remote file inclusion (RFI), local file inclusion (LFI)",
            "metadata_filter": {"control_family": ["File Handling"]}
        }
    },
    {
        "name": "SessionManagementAgent",
        "description": "Checks for secure session handling, token management, and protection against session hijacking.",
        "domain_query": {
            "keywords": "session management, session fixation, session hijacking, cookie security, insecure session tokens, session timeout, CSRF, cross-site request forgery, JWT session tokens",
            "metadata_filter": {"control_family": ["Session Management"]}
        }
    },
    {
        "name": "ValidationAgent",
        "description": "Focuses on input validation, output encoding, and prevention of injection attacks like SQLi and XSS.",
        "domain_query": {
            "keywords": "input validation, output encoding, SQL injection (SQLi), Cross-Site Scripting (XSS), command injection, type validation, sanitization, denylisting, allowlisting, parameter tampering",
            "metadata_filter": {"control_family": ["Encoding and Sanitization", "Validation and Business Logic"]}
        }
    }
]

PROMPT_TEMPLATES = []
for agent in AGENT_DEFINITIONS:
    agent_name = agent["name"]
    
    # Define the new template strings
    audit_template = """You are an expert security auditor. Your task is to audit the provided code for vulnerabilities based on the given patterns.
1.  Analyze the `<CODE_BUNDLE>` below.
2.  Use the `<VULNERABILITY_PATTERNS>` to identify specific anti-patterns and vulnerabilities.
3.  For each vulnerability you find, provide a detailed finding. This MUST include:
    - A concise 'title'.
    - A 'description' of the root cause.
    - 'severity' and 'confidence' ratings.
    - The 'line_number' where the vulnerability occurs.
    - A full CVSS 3.1 'cvss_vector' string (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').
    - A detailed 'remediation' guide.
    - A list of technical 'keywords' that characterize the vulnerability.
4.  Do NOT suggest any code fixes.

<VULNERABILITY_PATTERNS>
{vulnerability_patterns}
</VULNERABILITY_PATTERNS>

<CODE_BUNDLE>
{code_bundle}
</CODE_BUNDLE>

Respond ONLY with a valid JSON object that conforms to the InitialAnalysisResponse schema, containing a list of findings.
"""

    remediation_template = """You are an expert security engineer. Your task is to find and fix vulnerabilities in the provided code.
1.  Analyze the `<CODE_BUNDLE>` below.
2.  Use the `<VULNERABILITY_PATTERNS>` to identify specific anti-patterns and vulnerabilities.
3.  Use the `<SECURE_PATTERNS>` as a guide to write correct and secure code.
4.  For each vulnerability you find, provide a detailed finding AND a suggested code fix. The finding MUST include:
    - A concise 'title'.
    - A 'description' of the root cause.
    - 'severity' and 'confidence' ratings.
    - The 'line_number' where the vulnerability occurs.
    - A full CVSS 3.1 'cvss_vector' string (e.g., 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').
    - A detailed 'remediation' guide.
    - A list of technical 'keywords' that characterize the vulnerability.
    - A 'fix' object containing the exact 'original_snippet' to be replaced and the new 'code'.
5.  The `code` in your `fix` object must be a **surgical, drop-in replacement** for the `original_snippet`. It must ONLY contain the specific lines of code that are changing. Do NOT include any surrounding, unchanged code like function or class definitions, import statements, or block delimiters unless those elements are part of the vulnerable snippet itself.
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

    # QUICK_AUDIT Template
    PROMPT_TEMPLATES.append({
        "name": f"{agent_name} - Quick Audit",
        "template_type": "QUICK_AUDIT",
        "agent_name": agent_name,
        "version": 1,
        "template_text": audit_template
    })
    
    # DETAILED_REMEDIATION Template
    PROMPT_TEMPLATES.append({
        "name": f"{agent_name} - Detailed Remediation",
        "template_type": "DETAILED_REMEDIATION",
        "agent_name": agent_name,
        "version": 1,
        "template_text": remediation_template
    })
    
# Add the common CHAT prompt template (this one remains unchanged)
PROMPT_TEMPLATES.append({
    "name": "SecurityAdvisorPrompt",
    "template_type": "CHAT",
    "agent_name": "SecurityAdvisorAgent",
    "version": 1,
    "template_text": """You are an expert AI Security Advisor. Your role is to provide clear, accurate, and helpful advice on software security.
Use the provided conversation history and security context to answer the user's question.
If the context is not relevant, rely on your general security knowledge. Be concise and helpful.

<CONVERSATION_HISTORY>
{history_str}
</CONVERSATION_HISTORY>

<SECURITY_CONTEXT_FROM_KNOWLEDGE_BASE>
{rag_context}
</SECURITY_CONTEXT_FROM_KNOWLEDGE_BASE>

Current User Question: "{user_question}"

Provide your response as a single, helpful answer in a valid JSON object conforming to the ChatResponse schema."""
})


async def main():
    logger.info("Starting database population script...")
    if not settings.ASYNC_DATABASE_URL:
        raise ValueError("ASYNC_DATABASE_URL not set!")

    engine = create_async_engine(settings.ASYNC_DATABASE_URL)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with session_factory() as session:
        # Repositories
        framework_repo = FrameworkRepository(session)
        agent_repo = AgentRepository(session)
        prompt_repo = PromptTemplateRepository(session)

        # --- DELETION LOGIC ---
        # Get names of all items to be managed by this script
        framework_name = FRAMEWORK_DATA['name']
        agent_names = [agent['name'] for agent in AGENT_DEFINITIONS] + ["SecurityAdvisorAgent"]

        logger.info("Deleting existing data managed by this script to ensure a clean slate...")
        # Delete in reverse order of dependency: mappings -> prompts -> agents -> frameworks
        # This is safer than deleting all records from the tables.
        
        # 1. Delete framework-agent mappings associated with the framework
        framework_to_delete = await session.execute(
            select(db_models.Framework)
            .options(selectinload(db_models.Framework.agents))
            .where(db_models.Framework.name == framework_name)
        )
        framework_obj = framework_to_delete.scalars().first()
        if framework_obj:
            framework_obj.agents = []
            await session.commit()

        # 2. Delete prompt templates
        await session.execute(delete(db_models.PromptTemplate).where(db_models.PromptTemplate.agent_name.in_(agent_names)))

        # 3. Delete agents
        await session.execute(delete(db_models.Agent).where(db_models.Agent.name.in_(agent_names)))

        # 4. Delete framework
        await session.execute(delete(db_models.Framework).where(db_models.Framework.name == framework_name))
        
        await session.commit()
        logger.info("Deletion of old data complete.")
        # --- END DELETION LOGIC ---


        # 1. Create Framework
        logger.info(f"Creating framework: {FRAMEWORK_DATA['name']}")
        framework_create_model = api_models.FrameworkCreate(**FRAMEWORK_DATA)
        # Removed try/except to ensure it fails loudly if something is wrong
        db_framework = await framework_repo.create_framework(framework_create_model)
        logger.info(f"Framework '{db_framework.name}' created with ID: {db_framework.id}")

        # 2. Create Agents
        created_agent_ids = []
        for agent_def in AGENT_DEFINITIONS:
            logger.info(f"Creating agent: {agent_def['name']}")
            agent_create_model = api_models.AgentCreate(**agent_def)
            # Removed try/except
            db_agent = await agent_repo.create_agent(agent_create_model)
            created_agent_ids.append(db_agent.id)

        # 3. Create New Prompt Templates
        for template_def in PROMPT_TEMPLATES:
            logger.info(f"Creating prompt template: {template_def['name']}")
            template_create_model = api_models.PromptTemplateCreate(**template_def)
            await prompt_repo.create_template(template_create_model)

        # 4. Associate Agents with Framework
        logger.info(f"Associating {len(created_agent_ids)} agents with framework '{db_framework.name}'.")
        if created_agent_ids:
            await framework_repo.update_agent_mappings_for_framework(db_framework.id, created_agent_ids)
        
        logger.info("Database population script finished successfully!")

if __name__ == "__main__":
    asyncio.run(main())