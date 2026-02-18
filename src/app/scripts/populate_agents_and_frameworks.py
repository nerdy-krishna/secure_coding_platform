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

FRAMEWORKS_DATA = [
    {
        "name": "asvs",
        "description": "The OWASP Application Security Verification Standard (ASVS) is a standard for performing application security verifications."
    },
    {
        "name": "proactive_controls",
        "description": "OWASP Proactive Controls for Developers."
    },
    {
        "name": "cheatsheets",
        "description": "OWASP Cheatsheets Series."
    }
]

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
    },
    {
        "name": "BuildDeploymentAgent",
        "description": "Ensures security in the build and deployment pipeline, including CI/CD security and reproducible builds.",
        "domain_query": {
            "keywords": "build security, deployment security, CI/CD, pipeline security, reproducible builds, software bill of materials, SBOM, artifact integrity, git security",
            "metadata_filter": {"control_family": ["Build and Deployment"]}
        }
    },
    {
        "name": "ClientSideAgent",
        "description": "Analyzes client-side security risks, including DOM XSS, WebRTC, and modern frontend framework vulnerabilities.",
        "domain_query": {
            "keywords": "client-side security, DOM XSS, WebRTC, frontend security, CORS, CSP, subresource integrity, javascript security, browser security",
            "metadata_filter": {"control_family": ["Client Side"]}
        }
    },
    {
        "name": "CloudContainerAgent",
        "description": "Focuses on cloud-native security, container hardening, and orchestration security.",
        "domain_query": {
            "keywords": "cloud security, container security, docker security, kubernetes, orchestration, cloud misconfiguration, serverless security, cloud storage, IAM roles",
            "metadata_filter": {"control_family": ["Cloud and Container"]}
        }
    }
]

PROMPT_TEMPLATES = []
for agent in AGENT_DEFINITIONS:
    agent_name = agent["name"]
    
    # Define the new template strings
    audit_template = """You are an expert security auditor. Your task is to audit the provided code for vulnerabilities based on the given patterns.

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

    remediation_template = """You are an expert security engineer. Your task is to find and fix vulnerabilities in the provided code.

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

    # QUICK_AUDIT Template
    PROMPT_TEMPLATES.append({
        "name": f"{agent_name} - Quick Audit",
        "template_type": "QUICK_AUDIT",
        "agent_name": agent_name,
        "version": 2,
        "template_text": audit_template
    })
    
    # DETAILED_REMEDIATION Template
    PROMPT_TEMPLATES.append({
        "name": f"{agent_name} - Detailed Remediation",
        "template_type": "DETAILED_REMEDIATION",
        "agent_name": agent_name,
        "version": 2,
        "template_text": remediation_template
    })
    
# Add the common CHAT prompt template
PROMPT_TEMPLATES.append({
    "name": "SecurityAdvisorPrompt",
    "template_type": "CHAT",
    "agent_name": "SecurityAdvisorAgent",
    "version": 2,
    "template_text": """You are an expert AI Security Advisor. Your role is to provide clear, accurate, and helpful advice on software security.

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
        framework_names_in_script = [fw['name'] for fw in FRAMEWORKS_DATA]
        agent_names = [agent['name'] for agent in AGENT_DEFINITIONS] + ["SecurityAdvisorAgent"]

        logger.info("Deleting existing data managed by this script to ensure a clean slate...")
        
        # 1. Delete framework-agent mappings associated with ANY of the target frameworks
        # Also clean up legacy names
        target_framework_names = framework_names_in_script + ["OWASP ASVS", "OWASP ASVS v5.0", "OWASP Cheatsheets", "OWASP Proactive Controls"]
        
        frameworks_to_clear = await session.execute(
            select(db_models.Framework)
            .options(selectinload(db_models.Framework.agents))
            .where(db_models.Framework.name.in_(target_framework_names))
        )
        for framework_obj in frameworks_to_clear.scalars().all():
            logger.info(f"Clearing agent mappings for framework: {framework_obj.name}")
            framework_obj.agents = []
        
        await session.commit()

        # 2. Delete prompt templates
        await session.execute(delete(db_models.PromptTemplate).where(db_models.PromptTemplate.agent_name.in_(agent_names)))

        # 3. Delete agents
        await session.execute(delete(db_models.Agent).where(db_models.Agent.name.in_(agent_names)))

        # 4. Delete frameworks managed by this script
        await session.execute(delete(db_models.Framework).where(db_models.Framework.name.in_(target_framework_names)))

        await session.commit()
        logger.info("Deletion of old data complete.")
        # --- END DELETION LOGIC ---


        # 1. Create Frameworks
        created_frameworks = {}
        for fw_def in FRAMEWORKS_DATA:
            logger.info(f"Creating framework: {fw_def['name']}")
            framework_create_model = api_models.FrameworkCreate(**fw_def)
            db_framework = await framework_repo.create_framework(framework_create_model)
            created_frameworks[fw_def['name']] = db_framework
            logger.info(f"Framework '{db_framework.name}' created with ID: {db_framework.id}")

        # 2. Create Agents
        created_agent_ids = []
        for agent_def in AGENT_DEFINITIONS:
            logger.info(f"Creating agent: {agent_def['name']}")
            agent_create_model = api_models.AgentCreate(**agent_def)
            db_agent = await agent_repo.create_agent(agent_create_model)
            created_agent_ids.append(db_agent.id)

        # 3. Create New Prompt Templates
        for template_def in PROMPT_TEMPLATES:
            logger.info(f"Creating prompt template: {template_def['name']}")
            template_create_model = api_models.PromptTemplateCreate(**template_def)
            await prompt_repo.create_template(template_create_model)

        # 4. Associate Agents with Frameworks
        # For now, we associate ALL agents with ALL frameworks for simplicity, 
        # or we could strictly associate them with ASVS. 
        # The user seems to want them "visible", so having agents is good?
        # Actually, previously only ASVS had agents. 
        # Proactive Controls and Cheatsheets are "Knowledge Base" (mostly context), 
        # but agents might reference them if patterns match.
        # Let's associate agents with ALL of them so they can be selected in the chat modal 
        # (if the modal filters by "has agents" ?? No, modal just shows frameworks).
        
        # Let's associate agents primarily with ASVS as before, 
        # but maybe also the others so they appear "functional".
        # If I don't associate agents, they might appear as "None" in the table (which is what the user saw for ASVS? wait).
        
        # Let's associate agents with ALL frameworks in this list to be safe and consistent.
        if created_agent_ids:
            for fw_name, db_fw in created_frameworks.items():
                logger.info(f"Associating {len(created_agent_ids)} agents with framework '{db_fw.name}'.")
                await framework_repo.update_agent_mappings_for_framework(db_fw.id, created_agent_ids)
        
        logger.info("Database population script finished successfully!")

if __name__ == "__main__":
    asyncio.run(main())