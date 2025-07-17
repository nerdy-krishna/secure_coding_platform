# src/app/scripts/populate_agents_and_frameworks.py
import asyncio
import logging

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.config.config import settings
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
        "domain_query": "access control, authorization, user permissions, roles, insecure direct object reference (IDOR), privileges, broken object level authorization, function level authorization"
    },
    {
        "name": "ApiSecurityAgent",
        "description": "Focuses on the security of API endpoints, including REST, GraphQL, and other web services.",
        "domain_query": "API security, REST, GraphQL, API keys, rate limiting, API authentication, API authorization, endpoint security, JWT, OAuth, mass assignment"
    },
    {
        "name": "ArchitectureAgent",
        "description": "Assesses the overall security architecture, design patterns, and data flow.",
        "domain_query": "security architecture, design patterns, data flow, trust boundaries, tiering, segregation, component separation, security principles, microservices security"
    },
    {
        "name": "AuthenticationAgent",
        "description": "Scrutinizes login mechanisms, password policies, multi-factor authentication, and credential management.",
        "domain_query": "authentication, login, password policies, credential management, multi-factor authentication (MFA), single sign-on (SSO), password hashing, forgot password, remember me"
    },
    {
        "name": "BusinessLogicAgent",
        "description": "Looks for flaws in the application's business logic that could be exploited.",
        "domain_query": "business logic vulnerabilities, workflow abuse, race conditions, unexpected application state, feature misuse, price manipulation, excessive computation"
    },
    {
        "name": "CodeIntegrityAgent",
        "description": "Verifies the integrity of code and dependencies to prevent tampering.",
        "domain_query": "software integrity, code signing, dependency security, supply chain attacks, insecure deserialization, code tampering, third-party libraries, SCA, software composition analysis"
    },
    {
        "name": "CommunicationAgent",
        "description": "Checks for secure data transmission, use of TLS, and protection against network-level attacks.",
        "domain_query": "secure communication, TLS, SSL, HTTPS, certificate validation, weak ciphers, transport layer security, data in transit, network security protocols"
    },
    {
        "name": "ConfigurationAgent",
        "description": "Inspects for misconfigurations in the application, server, or third-party services.",
        "domain_query": "security misconfiguration, default credentials, verbose error messages, unnecessary features, improper server hardening, security headers, file permissions"
    },
    {
        "name": "CryptographyAgent",
        "description": "Evaluates the use of encryption, hashing algorithms, and key management.",
        "domain_query": "cryptography, encryption, hashing algorithms, weak ciphers, key management, PRNG, random number generation, IV, initialization vector, broken cryptography"
    },
    {
        "name": "DataProtectionAgent",
        "description": "Focuses on the protection of sensitive data at rest and in transit, including PII.",
        "domain_query": "data protection, sensitive data exposure, PII, personally identifiable information, data at rest, data classification, data masking, tokenization, GDPR, CCPA"
    },
    {
        "name": "ErrorHandlingAgent",
        "description": "Analyzes error handling routines to prevent information leakage.",
        "domain_query": "error handling, information leakage, stack traces, verbose error messages, debugging information exposure, exception handling, logging sensitive information"
    },
    {
        "name": "FileHandlingAgent",
        "description": "Scrutinizes file upload, download, and processing functionality for vulnerabilities.",
        "domain_query": "file handling, file upload vulnerabilities, path traversal, directory traversal, unrestricted file upload, malware upload, remote file inclusion (RFI), local file inclusion (LFI)"
    },
    {
        "name": "SessionManagementAgent",
        "description": "Checks for secure session handling, token management, and protection against session hijacking.",
        "domain_query": "session management, session fixation, session hijacking, cookie security, insecure session tokens, session timeout, CSRF, cross-site request forgery, JWT session tokens"
    },
    {
        "name": "ValidationAgent",
        "description": "Focuses on input validation, output encoding, and prevention of injection attacks like SQLi and XSS.",
        "domain_query": "input validation, output encoding, SQL injection (SQLi), Cross-Site Scripting (XSS), command injection, type validation, sanitization, denylisting, allowlisting, parameter tampering"
    }
]

PROMPT_TEMPLATES = []
for agent in AGENT_DEFINITIONS:
    agent_name = agent["name"]
    
    # Define the template strings clearly
    quick_audit_template = """You are an expert security auditor. Your task is to audit the provided code for vulnerabilities.
1.  Analyze the `<CODE_BUNDLE>` below.
2.  Use the `<VULNERABILITY_PATTERNS>` to identify specific anti-patterns and vulnerabilities.
3.  For each vulnerability you find, provide a detailed finding with a concise 'title'. Do NOT suggest code fixes.

<VULNERABILITY_PATTERNS>
{vulnerability_patterns}
</VULNERABILITY_PATTERNS>

<CODE_BUNDLE>
{code_bundle}
</CODE_BUNDLE>

Respond ONLY with a valid JSON object that conforms to the AuditResponse schema."""

    detailed_remediation_template = """You are an expert security engineer. Your task is to find and fix vulnerabilities in the provided code.
1.  Analyze the `<CODE_BUNDLE>` below.
2.  Use the `<VULNERABILITY_PATTERNS>` to identify specific anti-patterns and vulnerabilities.
3.  Use the `<SECURE_PATTERNS>` as a guide to write correct and secure code.
4.  For each vulnerability you find, provide a 'finding' and a 'suggestion' with a precise 'original_snippet' to be replaced.

<VULNERABILITY_PATTERNS>
{vulnerability_patterns}
</VULNERABILITY_PATTERNS>

<SECURE_PATTERNS>
{secure_patterns}
</SECURE_PATTERNS>

<CODE_BUNDLE>
{code_bundle}
</CODE_BUNDLE>

Respond ONLY with a valid JSON object that conforms to the RemediateResponse schema."""

    # QUICK_AUDIT Template
    PROMPT_TEMPLATES.append({
        "name": f"{agent_name} - Quick Audit",
        "template_type": "QUICK_AUDIT",
        "agent_name": agent_name,
        "version": 1,
        "template_text": quick_audit_template
    })
    
    # DETAILED_REMEDIATION Template
    PROMPT_TEMPLATES.append({
        "name": f"{agent_name} - Detailed Remediation",
        "template_type": "DETAILED_REMEDIATION",
        "agent_name": agent_name,
        "version": 1,
        "template_text": detailed_remediation_template
    })
    
# Add the common CHAT prompt template
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

        # 1. Create Framework
        logger.info(f"Creating framework: {FRAMEWORK_DATA['name']}")
        framework_create_model = api_models.FrameworkCreate(**FRAMEWORK_DATA)
        try:
            db_framework = await framework_repo.create_framework(framework_create_model)
            logger.info(f"Framework '{db_framework.name}' created with ID: {db_framework.id}")
        except Exception:
            logger.warning(f"Framework '{FRAMEWORK_DATA['name']}' likely already exists. Fetching it.")
            fw_list = await framework_repo.get_all_frameworks()
            db_framework = next((f for f in fw_list if f.name == FRAMEWORK_DATA['name']), None)
            if not db_framework:
                logger.error("Could not create or fetch framework. Exiting.")
                return

        # 2. Create Agents
        created_agent_ids = []
        for agent_def in AGENT_DEFINITIONS:
            logger.info(f"Creating agent: {agent_def['name']}")
            agent_create_model = api_models.AgentCreate(**agent_def)
            try:
                db_agent = await agent_repo.create_agent(agent_create_model)
                created_agent_ids.append(db_agent.id)
            except Exception:
                logger.warning(f"Agent '{agent_def['name']}' likely already exists. Skipping creation.")
                all_agents = await agent_repo.get_all_agents()
                existing_agent = next((a for a in all_agents if a.name == agent_def['name']), None)
                if existing_agent:
                    created_agent_ids.append(existing_agent.id)

        # 3. Create Prompt Templates
        for template_def in PROMPT_TEMPLATES:
            logger.info(f"Creating prompt template: {template_def['name']}")
            template_create_model = api_models.PromptTemplateCreate(**template_def)
            try:
                await prompt_repo.create_template(template_create_model)
            except Exception:
                logger.warning(f"Prompt template '{template_def['name']}' likely already exists. Skipping.")

        # 4. Associate Agents with Framework
        logger.info(f"Associating {len(created_agent_ids)} agents with framework '{db_framework.name}'.")
        if created_agent_ids:
            await framework_repo.update_agent_mappings_for_framework(db_framework.id, created_agent_ids)
        
        logger.info("Database population script finished successfully!")


if __name__ == "__main__":
    asyncio.run(main())