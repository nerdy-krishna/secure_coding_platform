# src/app/db/crud.py

import logging
import uuid
import datetime # Added import
from typing import List, Dict, Optional, Any

from sqlalchemy import String, case, cast, func, select, update, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, aliased

# Correctly import all models from a single source of truth
from app.db import models as db_models
from app.api import models as api_models
from app.agents import schemas as agent_schemas
from app.utils.encryption import FernetEncrypt
from app.analysis.repository_map import RepositoryMap

logger = logging.getLogger(__name__)

# === LLMConfiguration CRUD Functions ===


async def get_llm_config(
    db: AsyncSession, config_id: uuid.UUID
) -> Optional[db_models.LLMConfiguration]:
    """Retrieves a single LLM configuration by its ID."""
    result = await db.execute(
        select(db_models.LLMConfiguration).filter(
            db_models.LLMConfiguration.id == config_id
        )
    )
    return result.scalars().first()


async def get_llm_config_with_decrypted_key(
    db: AsyncSession, config_id: uuid.UUID
) -> Optional[db_models.LLMConfiguration]:
    """Retrieves an LLM config and adds a temporary 'decrypted_api_key' attribute."""
    config = await get_llm_config(db, config_id)
    if config:
        setattr(
            config, "decrypted_api_key", FernetEncrypt.decrypt(config.encrypted_api_key)
        )
    return config


async def get_llm_configs(
    db: AsyncSession, skip: int = 0, limit: int = 100
) -> List[db_models.LLMConfiguration]:
    """Retrieves a list of all LLM configurations."""
    result = await db.execute(
        select(db_models.LLMConfiguration)
        .order_by(db_models.LLMConfiguration.name)
        .offset(skip)
        .limit(limit)
    )
    return list(result.scalars().all())


async def create_llm_config(
    db: AsyncSession, config: api_models.LLMConfigurationCreate
) -> db_models.LLMConfiguration:
    """
    Creates a new LLM configuration, encrypting the API key and saving all fields.
    """
    encrypted_key = FernetEncrypt.encrypt(config.api_key)
    
    # Create the database model instance with all fields from the API model
    db_config = db_models.LLMConfiguration(
        name=config.name,
        provider=config.provider,
        model_name=config.model_name,
        encrypted_api_key=encrypted_key,
        # --- ADDED: Save the new dynamic fields to the database ---
        tokenizer_encoding=config.tokenizer_encoding,
        input_cost_per_million=config.input_cost_per_million,
        output_cost_per_million=config.output_cost_per_million,
    )
    db.add(db_config)
    await db.commit()
    await db.refresh(db_config)
    return db_config

async def update_llm_config(                                                                                                                                                                                       
    db: AsyncSession, config_id: uuid.UUID, config_update: api_models.LLMConfigurationUpdate                                                                                                                       
) -> Optional[db_models.LLMConfiguration]:                                                                                                                                                                         
    """Updates an existing LLM configuration.                                                                                                                                                                      
    Assumes config_update contains fields like 'input_cost_per_million',                                                                                                                                           
    'output_cost_per_million', 'tokenizer_encoding' if they are to be updated.                                                                                                                                     
    """                                                                                                                                                                                                            
    db_config = await get_llm_config(db, config_id)                                                                                                                                                                
    if not db_config:                                                                                                                                                                                              
        return None                                                                                                                                                                                                
                                                                                                                                                                                                                   
    update_data = config_update.model_dump(exclude_unset=True)                                                                                                                                                     
                                                                                                                                                                                                                   
    for key, value in update_data.items():                                                                                                                                                                         
        if key == "api_key":                                                                                                                                                                                       
            if value:  # Only update if a new, non-empty key is provided                                                                                                                                           
                db_config.encrypted_api_key = FernetEncrypt.encrypt(value)                                                                                                                                         
        elif hasattr(db_config, key):                                                                                                                                                                              
            setattr(db_config, key, value)                                                                                                                                                                         
        # Note: If Pydantic model field names (e.g., 'input_token_cost') were different                                                                                                                            
        # from DB model field names (e.g., 'input_cost_per_million'),                                                                                                                                              
        # explicit mapping would be needed here.                                                                                                                                                                   
        # However, create_llm_config suggests Pydantic models use DB-like names.                                                                                                                                   
                                                                                                                                                                                                                   
    await db.commit()                                                                                                                                                                                              
    await db.refresh(db_config)                                                                                                                                                                                    
    return db_config

async def delete_llm_config(
    db: AsyncSession, config_id: uuid.UUID
) -> Optional[db_models.LLMConfiguration]:
    """Deletes an LLM configuration by its ID."""
    config = await get_llm_config(db, config_id)
    if config:
        await db.delete(config)
        await db.commit()
    return config


# === User CRUD (Corrected) ===


async def get_user_by_email(db: AsyncSession, email: str) -> Optional[db_models.User]:
    """Retrieves a user by their email address."""
    result = await db.execute(select(db_models.User).filter(db_models.User.email == email))
    return result.scalars().first()

# === Submission & Analysis CRUD ===


async def create_submission(
    db: AsyncSession,
    user_id: int,
    project_name: str,
    repo_url: Optional[str] = None,
    files: Optional[List[Dict[str, Any]]] = None,
    frameworks: Optional[List[str]] = None,
    excluded_files: Optional[List[str]] = None,
    main_llm_config_id: Optional[uuid.UUID] = None,
    specialized_llm_config_id: Optional[uuid.UUID] = None,
) -> db_models.CodeSubmission:
    """Creates a new code submission record."""
    submission = db_models.CodeSubmission(
        user_id=user_id,
        project_name=project_name,
        repo_url=repo_url,
        status="Pending",
        frameworks=frameworks,
        excluded_files=excluded_files,
        main_llm_config_id=main_llm_config_id,
        specialized_llm_config_id=specialized_llm_config_id,
    )
    db.add(submission)
    await db.commit()
    await db.refresh(submission)

    if files:
        await add_files_to_submission(db, submission.id, files)

    return submission


async def add_files_to_submission(
    db: AsyncSession, submission_id: uuid.UUID, files: List[Dict[str, Any]]
):
    """Adds multiple files to an existing submission."""
    db_files = [
        db_models.SubmittedFile(
            submission_id=submission_id,
            file_path=file["path"],
            content=file["content"],
            language=file.get("language", "unknown"),
        )
        for file in files
    ]
    db.add_all(db_files)
    await db.commit()                                                                                                                                                                                              
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
async def get_submitted_files_for_submission(                                                                                                                                                                      
    db: AsyncSession, submission_id: uuid.UUID                                                                                                                                                                     
) -> List[db_models.SubmittedFile]:                                                                                                                                                                                
    """Retrieves all submitted files for a given submission ID."""                                                                                                                                                 
    result = await db.execute(                                                                                                                                                                                     
        select(db_models.SubmittedFile).filter(                                                                                                                                                                    
            db_models.SubmittedFile.submission_id == submission_id                                                                                                                                                 
        )                                                                                                                                                                                                          
    )                                                                                                                                                                                                              
    return list(result.scalars().all())                                                                                                                                                                            
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
async def get_submission(                                                                                                                                                                                          
    db: AsyncSession, submission_id: uuid.UUID                                                                                                                                                                     
) -> Optional[db_models.CodeSubmission]:
    """Retrieves a submission by ID, with related files and findings."""
    result = await db.execute(
        select(db_models.CodeSubmission)
        .options(
            selectinload(db_models.CodeSubmission.files),
            selectinload(db_models.CodeSubmission.findings).selectinload(
                db_models.VulnerabilityFinding.fixes
            ),
        )
        .filter(db_models.CodeSubmission.id == submission_id)
    )
    return result.scalars().first()


async def update_submission_status(
    db: AsyncSession, submission_id: uuid.UUID, status: str
):
    """Updates the status of a submission."""
    stmt = (
        update(db_models.CodeSubmission)
        .where(db_models.CodeSubmission.id == submission_id)
        .values(status=status)
    )
    await db.execute(stmt)
    await db.commit()

async def update_submission_file_context(
    db: AsyncSession, file_id: int, context: Dict[str, Any]
):
    """Updates the analysis context for a single file."""
    stmt = (
        update(db_models.SubmittedFile)
        .where(db_models.SubmittedFile.id == file_id)
        .values(asvs_analysis=context) # Assuming context is saved to asvs_analysis
    )
    await db.execute(stmt)
    await db.commit()

async def save_llm_interaction(
    db: AsyncSession, interaction_data: agent_schemas.LLMInteraction
):
    """Saves a record of an interaction with an LLM."""
    db_interaction = db_models.LLMInteraction(**interaction_data.model_dump())
    db.add(db_interaction)
    await db.commit()


async def save_findings(
    db: AsyncSession,
    submission_id: uuid.UUID,
    findings: List[agent_schemas.VulnerabilityFinding],
) -> List[db_models.VulnerabilityFinding]:
    """Saves a list of vulnerability findings and returns the persisted objects."""
    if not findings:
        return []

    db_findings = [
        db_models.VulnerabilityFinding(
            submission_id=submission_id,
            file_path=finding.file_path,
            cwe=finding.cwe,
            description=finding.description,
            severity=finding.severity,
            line_number=finding.line_number,
            remediation=finding.remediation,
            confidence=finding.confidence,
            references=finding.references,
        )
        for finding in findings
    ]
    db.add_all(db_findings)
    await db.flush()
    for finding in db_findings:
        await db.refresh(finding)
    await db.commit()
    return db_findings


async def save_fix_suggestion(
    db: AsyncSession, finding_id: int, suggestion: agent_schemas.FixSuggestion
):
    """Saves a code fix suggestion for a specific vulnerability finding."""
    fix = db_models.FixSuggestion(
        finding_id=finding_id,
        description=suggestion.description,
        suggested_fix=suggestion.code,
    )
    db.add(fix)
    await db.commit()

async def get_paginated_results(db: AsyncSession, user_id: int, skip: int = 0, limit: int = 10, search: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves a paginated list of completed submissions with aggregated finding counts.
    Supports searching by project name or submission ID.
    """
    # Subquery to count findings per severity for each submission
    finding_counts_subquery = (
        select(
            db_models.VulnerabilityFinding.submission_id,
            func.count(db_models.VulnerabilityFinding.id).label("total_findings"),
            func.sum(case((func.upper(db_models.VulnerabilityFinding.severity) == 'CRITICAL', 1), else_=0)).label("critical_findings"),
            func.sum(case((func.upper(db_models.VulnerabilityFinding.severity) == 'HIGH', 1), else_=0)).label("high_findings"),
            func.sum(case((func.upper(db_models.VulnerabilityFinding.severity) == 'MEDIUM', 1), else_=0)).label("medium_findings"),
            func.sum(case((func.upper(db_models.VulnerabilityFinding.severity) == 'LOW', 1), else_=0)).label("low_findings"),
        )
        .group_by(db_models.VulnerabilityFinding.submission_id)
        .subquery()
    )

    # Main query to select completed submissions
    stmt = (
        select(
            db_models.CodeSubmission,
            finding_counts_subquery.c.total_findings,
            finding_counts_subquery.c.critical_findings,
            finding_counts_subquery.c.high_findings,
            finding_counts_subquery.c.medium_findings,
            finding_counts_subquery.c.low_findings,
        )
        .outerjoin(finding_counts_subquery, db_models.CodeSubmission.id == finding_counts_subquery.c.submission_id)
        .where(
            db_models.CodeSubmission.user_id == user_id,
            db_models.CodeSubmission.status == "Completed"
        )
    )

    if search:
        project_name_filter = db_models.CodeSubmission.project_name.ilike(f"%{search}%")
        submission_id_filter = cast(db_models.CodeSubmission.id, String).ilike(f"%{search}%")
        stmt = stmt.filter(or_(project_name_filter, submission_id_filter))
    
    stmt = stmt.order_by(db_models.CodeSubmission.completed_at.desc().nulls_last()).offset(skip).limit(limit)
    
    result = await db.execute(stmt)
    
    # Process results into a list of dictionaries
    results_list = []
    for row in result.all():
        sub, total, critical, high, medium, low = row
        
        # Calculate risk score
        critical_count = critical or 0
        high_count = high or 0
        medium_count = medium or 0
        low_count = low or 0
        risk_score = (critical_count * 10) + (high_count * 5) + (medium_count * 2) + (low_count * 1)

        results_list.append({
            "submission_id": sub.id,
            "project_name": sub.project_name,
            "completed_at": sub.completed_at,
            "total_findings": total or 0,
            "critical_findings": critical_count,
            "high_findings": high_count,
            "medium_findings": medium_count,
            "low_findings": low_count,
            "risk_score": risk_score,
        })
        
    return results_list

async def get_paginated_results_count(db: AsyncSession, user_id: int, search: Optional[str] = None) -> int:
    """Counts the total number of completed submissions for a specific user, with optional search."""
    stmt = (
        select(func.count(db_models.CodeSubmission.id))
        .where(
            db_models.CodeSubmission.user_id == user_id,
            db_models.CodeSubmission.status == "Completed"
        )
    )
    if search:
        project_name_filter = db_models.CodeSubmission.project_name.ilike(f"%{search}%")
        submission_id_filter = cast(db_models.CodeSubmission.id, String).ilike(f"%{search}%")
        stmt = stmt.filter(or_(project_name_filter, submission_id_filter))

    result = await db.execute(stmt)
    count = result.scalar_one_or_none()
    return count or 0

    
async def get_submission_history(db: AsyncSession, user_id: int, skip: int = 0, limit: int = 10, search: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves a paginated list of all submissions for a specific user,
    including aggregated actual cost data and optional search on project name or submission ID.
    """
    # Alias LLMInteraction to perform aggregation
    llm_interaction_alias = aliased(db_models.LLMInteraction)

    # Subquery to aggregate costs and tokens per submission
    cost_subquery = (
        select(
            llm_interaction_alias.submission_id,
            func.sum(llm_interaction_alias.cost).label("total_cost"),
            func.sum(llm_interaction_alias.input_tokens).label("total_input_tokens"),
            func.sum(llm_interaction_alias.output_tokens).label("total_output_tokens"),
            func.sum(llm_interaction_alias.total_tokens).label("total_tokens"),
        )
        .group_by(llm_interaction_alias.submission_id)
        .subquery()
    )

    # Main query to fetch submissions and join with the cost aggregation
    stmt = (
        select(
            db_models.CodeSubmission,
            cost_subquery.c.total_cost,
            cost_subquery.c.total_input_tokens,
            cost_subquery.c.total_output_tokens,
            cost_subquery.c.total_tokens,
        )
        .outerjoin(
            cost_subquery,
            db_models.CodeSubmission.id == cost_subquery.c.submission_id,
        )
        .filter(db_models.CodeSubmission.user_id == user_id)
    )

    if search:
        # Search against the project name (case-insensitive)
        project_name_filter = db_models.CodeSubmission.project_name.ilike(f"%{search}%")
        
        # Search against the submission ID by casting it to a string
        submission_id_filter = cast(db_models.CodeSubmission.id, String).ilike(f"%{search}%")
        
        stmt = stmt.filter(or_(project_name_filter, submission_id_filter))

    stmt = stmt.order_by(db_models.CodeSubmission.submitted_at.desc()).offset(skip).limit(limit)

    result = await db.execute(stmt)
    
    # Process results into a list of dictionaries to pass to the API model
    results_with_cost = []
    for row in result.all():
        submission, total_cost, total_input, total_output, total_tokens = row
        submission_dict = {
            "id": submission.id,
            "project_name": submission.project_name,
            "status": submission.status,
            "submitted_at": submission.submitted_at,
            "completed_at": submission.completed_at,
            "estimated_cost": submission.estimated_cost,
            "actual_cost": {
                "total_cost": total_cost or 0.0,
                "total_input_tokens": total_input or 0,
                "total_output_tokens": total_output or 0,
                "total_tokens": total_tokens or 0,
            } if submission.status == "Completed" else None,
        }
        results_with_cost.append(submission_dict)

    return results_with_cost

async def get_submission_history_count(db: AsyncSession, user_id: int, search: Optional[str] = None) -> int:
    """Counts the total number of submissions for a specific user, with optional search."""
    stmt = (
        select(func.count(db_models.CodeSubmission.id))
        .filter(db_models.CodeSubmission.user_id == user_id)
    )
    if search:
        # Search against the project name (case-insensitive)
        project_name_filter = db_models.CodeSubmission.project_name.ilike(f"%{search}%")
        
        # Search against the submission ID by casting it to a string
        submission_id_filter = cast(db_models.CodeSubmission.id, String).ilike(f"%{search}%")
        
        stmt = stmt.filter(or_(project_name_filter, submission_id_filter))

    result = await db.execute(stmt)
    count = result.scalar_one_or_none()
    return count or 0

async def get_files_by_submission_id(db: AsyncSession, submission_id: uuid.UUID) -> List[db_models.SubmittedFile]:
    """
    Retrieves all submitted files associated with a given submission ID.
    """
    # FIX: Use the correct 'db_models' alias
    result = await db.execute(
        select(db_models.SubmittedFile).where(db_models.SubmittedFile.submission_id == submission_id)
    )
    # FIX: Explicitly convert Sequence to List to match type hint
    return list(result.scalars().all())

# === Repository Map Cache CRUD ===

async def get_repository_map_from_cache(db: AsyncSession, codebase_hash: str) -> Optional[RepositoryMap]:
    """
    Retrieves a cached RepositoryMap by the codebase hash.
    """
    result = await db.execute(
        select(db_models.RepositoryMapCache).filter(db_models.RepositoryMapCache.codebase_hash == codebase_hash)
    )
    cache_entry = result.scalars().first()
    if cache_entry:
        # Re-validate the JSON data back into our Pydantic model
        return RepositoryMap.model_validate(cache_entry.repository_map)
    return None


async def create_repository_map_cache(db: AsyncSession, codebase_hash: str, repository_map: RepositoryMap) -> db_models.RepositoryMapCache:
    """
    Saves a new RepositoryMap to the cache.
    """
    # Convert the Pydantic model to a dictionary for JSONB storage
    db_cache_entry = db_models.RepositoryMapCache(
        codebase_hash=codebase_hash,
        repository_map=repository_map.model_dump()
    )
    db.add(db_cache_entry)
    await db.commit()
    await db.refresh(db_cache_entry)
    return db_cache_entry

async def update_submission_cost_and_status(
    db: AsyncSession, submission_id: uuid.UUID, status: str, estimated_cost: Dict[str, Any]
):
    """Updates the status and estimated_cost of a submission."""
    stmt = (
        update(db_models.CodeSubmission)
        .where(db_models.CodeSubmission.id == submission_id)
        .values(status=status, estimated_cost=estimated_cost)
    )
    await db.execute(stmt)
    await db.commit()


async def save_final_reports_and_status(
    db: AsyncSession,
    submission_id: uuid.UUID,
    status: str,
    impact_report: Optional[Dict[str, Any]] = None,
    sarif_report: Optional[Dict[str, Any]] = None,
):
    """
    Updates a submission with the final reports (impact and SARIF) and sets the final status.
    """
    # Make the datetime object naive for TIMESTAMP WITHOUT TIME ZONE columns
    completed_at_aware = datetime.datetime.now(datetime.timezone.utc)
    values_to_update = {"status": status, "completed_at": completed_at_aware}
    if impact_report:
        values_to_update["impact_report"] = impact_report
    if sarif_report:
        values_to_update["sarif_report"] = sarif_report
    
    stmt = (
        update(db_models.CodeSubmission)
        .where(db_models.CodeSubmission.id == submission_id)
        .values(**values_to_update)
    )
    await db.execute(stmt)
    await db.commit()

async def get_llm_interactions_for_user(db: AsyncSession, user_id: int) -> List[db_models.LLMInteraction]:
    """
    Retrieves all LLM interactions for a given user, ordered by most recent.
    """
    stmt = (
        select(db_models.LLMInteraction)
        .join(db_models.CodeSubmission, db_models.LLMInteraction.submission_id == db_models.CodeSubmission.id)
        .where(db_models.CodeSubmission.user_id == user_id)
        .order_by(db_models.LLMInteraction.timestamp.desc())
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())

async def delete_submission(db: AsyncSession, submission_id: uuid.UUID) -> bool:
    """
    Deletes a submission and all its related data by its ID.
    Returns True if the submission was found and deleted, False otherwise.
    """
    submission = await get_submission(db, submission_id)
    if not submission:
        return False
    
    await db.delete(submission)
    await db.commit()
    logger.info(f"Successfully deleted submission {submission_id} and all related data.")
    return True