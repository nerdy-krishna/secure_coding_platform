# src/app/api/v1/routers/admin_rag.py
import logging
import math
import uuid
import io
from typing import Any, Dict, List, cast, Optional
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    UploadFile,
    File,
    Form,
    status,
    BackgroundTasks,
)
import pandas as pd
from pydantic import BaseModel

from app.api.v1.dependencies import (
    get_framework_repository,
    get_rag_job_repository,
    get_rag_preprocessor_service,
    get_security_standards_service,
)
from app.api.v1 import models as api_models
from app.core.services.security_standards_service import SecurityStandardsService
from app.core.schemas import (
    EnrichedDocument,
    PreprocessingResponse,
    RAGJobStartResponse,
    RAGJobStatusResponse,
)
from app.core.services.rag_preprocessor_service import RAGPreprocessorService
from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.framework_repo import FrameworkRepository
from app.infrastructure.database.repositories.rag_job_repo import RAGJobRepository
from app.infrastructure.rag.rag_client import get_rag_service, RAGService
from app.api.v1.models import RAGDocumentDeleteRequest

logger = logging.getLogger(__name__)
rag_router = APIRouter(prefix="/rag", tags=["Admin: RAG Management"])





class ReprocessRequest(BaseModel):
    framework_name: str
    target_languages: List[str]
    llm_config_id: uuid.UUID


@rag_router.post("/preprocess/reprocess", response_model=RAGJobStartResponse)
async def reprocess_framework(
    request: ReprocessRequest,
    user: db_models.User = Depends(current_superuser),
    job_repo: RAGJobRepository = Depends(get_rag_job_repository),
    preprocessor: RAGPreprocessorService = Depends(get_rag_preprocessor_service),
):
    """
    Restart a preprocessing job using the original content from the latest completed job
    for the given framework. This enables "Editing" without re-uploading the file.
    """
    latest_job = await job_repo.get_latest_job_for_framework(
        request.framework_name, user.id
    )

    if not latest_job or not latest_job.raw_content:
        raise HTTPException(
            status_code=404,
            detail=f"No previous completed job found for framework '{request.framework_name}' with content. Please upload the file again.",
        )

    # Calculate new cost estimate with potentially new parameters
    estimated_cost = await preprocessor.estimate_cost(
        latest_job.raw_content,
        request.llm_config_id,
        request.target_languages,
        previous_job_state=latest_job,
    )

    # Create a NEW job with the OLD content
    new_job = await job_repo.create_job(
        user_id=user.id,
        framework_name=request.framework_name,
        llm_config_id=request.llm_config_id,
        file_hash=latest_job.original_file_hash,
    )

    # Store the content and update status
    await job_repo.update_job(
        new_job.id,
        {
            "raw_content": latest_job.raw_content,
            "status": "PENDING_APPROVAL",
            "estimated_cost": estimated_cost,
        },
    )

    message = "Cost re-estimated for updated configuration. Please approve to start processing."

    return RAGJobStartResponse(
        job_id=new_job.id,
        framework_name=new_job.framework_name,
        status="PENDING_APPROVAL",
        estimated_cost=estimated_cost,
        message=message,
    )


@rag_router.post("/preprocess/start", response_model=RAGJobStartResponse)
async def start_preprocessing_job(
    file: UploadFile = File(...),
    llm_config_id: uuid.UUID = Form(...),
    framework_name: str = Form(...),
    target_languages: List[str] = Form([]),
    user: db_models.User = Depends(current_superuser),
    job_repo: RAGJobRepository = Depends(get_rag_job_repository),
    preprocessor: RAGPreprocessorService = Depends(get_rag_preprocessor_service),
):
    """
    Step 1: Starts a new RAG preprocessing job by hashing the file, checking for duplicates,
    calculating the cost, and returning a job ID for approval.
    """
    contents = await file.read()
    await file.seek(0)
    file_hash = job_repo.hash_content(contents)

    # Always treat as a new job and calculate the cost.
    job = await job_repo.create_job(
        user_id=user.id,
        framework_name=framework_name,
        llm_config_id=llm_config_id,
        file_hash=file_hash,
    )
    await job_repo.update_job(job.id, {"raw_content": contents})

    estimated_cost = await preprocessor.estimate_cost(
        contents, llm_config_id, target_languages
    )

    await job_repo.update_job(
        job.id, {"status": "PENDING_APPROVAL", "estimated_cost": estimated_cost}
    )
    message = "Cost estimated. Please approve to start processing."

    final_job_state = await job_repo.get_job_by_id(job.id, user.id)
    if not final_job_state:
        raise HTTPException(
            status_code=500, detail="Failed to retrieve job state after creation."
        )

    return RAGJobStartResponse(
        job_id=final_job_state.id,
        framework_name=final_job_state.framework_name,
        status=final_job_state.status,
        estimated_cost=final_job_state.estimated_cost,
        message=message,
    )


@rag_router.post("/preprocess/{job_id}/approve", status_code=status.HTTP_202_ACCEPTED)
async def approve_preprocessing_job(
    job_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    user: db_models.User = Depends(current_superuser),
    job_repo: RAGJobRepository = Depends(get_rag_job_repository),
    preprocessor: RAGPreprocessorService = Depends(get_rag_preprocessor_service),
):
    """
    Step 2: Approves and starts the actual LLM processing for a job as a background task.
    """
    job = await job_repo.get_job_by_id(job_id, user.id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    if job.status != "PENDING_APPROVAL":
        raise HTTPException(
            status_code=400,
            detail=f"Job is not awaiting approval. Status: {job.status}",
        )

    # If the job already has processed documents (from a duplicate run), we can complete it immediately.
    if job.processed_documents:
        await job_repo.update_job(job_id, {"status": "COMPLETED"})
        return {"message": "Existing job result approved. You can now ingest the data."}

    raw_content = job.raw_content
    if not raw_content:
        await job_repo.update_job(
            job_id,
            {"status": "FAILED", "error_message": "Original file content is missing."},
        )
        raise HTTPException(
            status_code=400,
            detail="Cannot process job, original file content is missing.",
        )

    await job_repo.update_job(job_id, {"status": "PROCESSING"})

    # Run the time-consuming task in the background
    background_tasks.add_task(
        preprocessor.run_preprocessing_job, job_id, user.id, raw_content
    )

    return {"message": "Job approved. Processing has started in the background."}


@rag_router.get("/preprocess/{job_id}/status", response_model=RAGJobStatusResponse)
async def get_preprocessing_job_status(
    job_id: uuid.UUID,
    user: db_models.User = Depends(current_superuser),
    job_repo: RAGJobRepository = Depends(get_rag_job_repository),
):
    """
    Step 3: Polls for the status and result of a preprocessing job.
    """
    job = await job_repo.get_job_by_id(job_id, user.id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    return RAGJobStatusResponse(
        job_id=job.id,
        framework_name=job.framework_name,
        status=job.status,
        estimated_cost=job.estimated_cost,
        actual_cost=job.actual_cost,
        processed_documents=[EnrichedDocument(**doc) for doc in job.processed_documents]
        if job.processed_documents
        else None,
        error_message=job.error_message,
    )


# --- Direct Ingestion and Management Endpoints ---


@rag_router.post("/ingest-processed", status_code=status.HTTP_201_CREATED)
async def ingest_processed_documents(
    payload: PreprocessingResponse,
    user: db_models.User = Depends(current_superuser),
    rag_service: RAGService = Depends(get_rag_service),
    framework_repo: FrameworkRepository = Depends(get_framework_repository),
):
    """
    Deletes all existing documents for a framework and ingests the new,
    processed documents. This is the final step after a job is complete.
    Also creates a Framework database record if one doesn't already exist.
    """
    try:
        framework_name = payload.framework_name
        documents = payload.processed_documents

        rag_service.delete_by_framework(framework_name)

        # Namespace IDs with framework name to avoid collisions in the shared collection.
        # E.g., "CWE-79" in a custom framework would collide with "CWE-79" in OWASP ASVS.
        ids = [f"{framework_name}::{doc.id}" for doc in documents]
        docs_to_add = [doc.enriched_content for doc in documents]
        metadatas = [doc.metadata for doc in documents]

        for i, meta in enumerate(metadatas):
            meta["framework_name"] = framework_name
            meta["scan_ready"] = payload.scan_ready
            meta["original_id"] = documents[i].id

        # Sanitize metadata: ChromaDB rejects NaN, None, and non-primitive values.
        # Pandas DataFrames produce NaN for empty cells which silently breaks ChromaDB add().
        sanitized_metadatas = []
        for meta in metadatas:
            clean = {}
            for k, v in meta.items():
                if v is None:
                    clean[k] = ""
                elif isinstance(v, float) and math.isnan(v):
                    clean[k] = ""
                elif isinstance(v, (str, int, float, bool)):
                    clean[k] = v
                else:
                    clean[k] = str(v)
            sanitized_metadatas.append(clean)

        logger.info(
            f"Ingesting {len(ids)} documents for framework '{framework_name}'. "
            f"IDs: {ids}, Metadata keys: {list(sanitized_metadatas[0].keys()) if sanitized_metadatas else []}"
        )

        rag_service.add(documents=docs_to_add, metadatas=sanitized_metadatas, ids=ids)

        # Auto-create a Framework DB record so it appears in the Knowledge Base
        existing_framework = await framework_repo.get_framework_by_name(framework_name)
        if not existing_framework:
            framework_data = api_models.FrameworkCreate(
                name=framework_name,
                description=f"Custom framework with {len(documents)} enriched documents.",
            )
            await framework_repo.create_framework(framework_data)
            logger.info(f"Auto-created framework record for '{framework_name}'.")

        return {
            "message": f"Successfully deleted old documents and ingested {len(documents)} new processed documents for framework '{framework_name}'."
        }
    except Exception as e:
        logger.error(
            f"Failed to ingest processed documents for {payload.framework_name}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail=f"An error occurred during processed ingestion: {e}"
        )


@rag_router.post("/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_documents(
    framework_name: str = Form(...),
    file: UploadFile = File(...),
    user: db_models.User = Depends(current_superuser),
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    (Legacy) Ingests raw documents from a CSV file directly without preprocessing.
    """
    if not file.filename or not file.filename.endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A CSV file with a valid filename is required.",
        )
    try:
        contents = await file.read()
        csv_file = io.StringIO(contents.decode("utf-8"))
        df = pd.read_csv(csv_file)

        if "id" not in df.columns or "document" not in df.columns:
            raise HTTPException(
                status_code=400,
                detail="CSV must contain 'id' and 'document' columns.",
            )

        ids = df["id"].astype(str).tolist()
        documents = df["document"].tolist()
        metadatas_raw = df.drop(columns=["id", "document"]).to_dict("records")
        metadatas = cast(List[Dict[str, Any]], metadatas_raw)

        for metadata in metadatas:
            metadata["framework_name"] = framework_name
            metadata["scan_ready"] = True

        rag_service.add(documents=documents, metadatas=metadatas, ids=ids)
        return {
            "message": f"Successfully ingested {len(documents)} documents for framework '{framework_name}'."
        }

    except Exception as e:
        logger.error(
            f"Failed to ingest documents for {framework_name}: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred during ingestion: {e}",
        )


@rag_router.get("/frameworks/{framework_name}", response_model=dict)
async def get_documents_for_framework(
    framework_name: str,
    user: db_models.User = Depends(current_superuser),
    rag_service: RAGService = Depends(get_rag_service),
):
    """Retrieves all documents associated with a specific framework."""
    try:
        return rag_service.get_by_framework(framework_name)
    except Exception as e:
        logger.error(
            f"Failed to retrieve documents for framework {framework_name}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Failed to retrieve documents from RAG service."
        )


@rag_router.delete("/documents", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rag_documents(
    request: RAGDocumentDeleteRequest,
    user: db_models.User = Depends(current_superuser),
    rag_service: RAGService = Depends(get_rag_service),
):
    """Deletes one or more documents from the RAG knowledge base by their IDs."""
    if not request.document_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No document IDs provided for deletion.",
        )
    try:
        rag_service.delete(ids=request.document_ids)
    except Exception as e:
        logger.error(
            f"Failed to delete documents: {request.document_ids}. Error: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Failed to delete documents from RAG service."
        )


# --- NEW Security Standards Ingestion Endpoints ---


@rag_router.get("/ingest/stats", response_model=Dict[str, int])
async def get_rag_stats(
    rag_service: RAGService = Depends(get_rag_service),
    user: db_models.User = Depends(current_superuser),
):
    """
    Get document counts for standard security frameworks.
    """
    if not rag_service:
        raise HTTPException(status_code=503, detail="RAG Service not available")

    return rag_service.get_framework_stats()


@rag_router.post(
    "/ingest/standards/{standard_type}", status_code=status.HTTP_201_CREATED
)
async def ingest_security_standard(
    standard_type: str,
    file: Optional[UploadFile] = File(None),
    url: Optional[str] = Form(None),
    user: db_models.User = Depends(current_superuser),
    standards_service: SecurityStandardsService = Depends(
        get_security_standards_service
    ),
):
    """
    Ingests a security standard into the RAG knowledge base.

    - **standard_type**: 'asvs', 'proactive-controls', 'cheatsheets'
    - **asvs**: Requires 'file' (CSV).
    - **proactive-controls**: Requires 'url' (GitHub Repo URL).
    - **cheatsheets**: Requires 'url' (GitHub Repo URL).
    """
    try:
        if standard_type == "asvs":
            if not file:
                raise HTTPException(
                    status_code=400, detail="ASVS requires a CSV file upload."
                )
            if not file.filename.endswith(".csv"):
                raise HTTPException(
                    status_code=400, detail="ASVS file must be a CSV file."
                )
            return await standards_service.ingest_asvs_csv(file, user_id=user.id)

        elif standard_type == "proactive-controls":
            if not url:
                raise HTTPException(
                    status_code=400, detail="Proactive Controls requires a GitHub URL."
                )
            return await standards_service.ingest_proactive_controls_github(
                url, user_id=user.id
            )

        elif standard_type == "cheatsheets":
            if not url:
                raise HTTPException(
                    status_code=400, detail="Cheatsheets requires a GitHub URL."
                )
            return await standards_service.ingest_cheatsheets_github(
                url, user_id=user.id
            )

        else:
            raise HTTPException(
                status_code=400, detail=f"Unsupported standard type: {standard_type}"
            )

    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Failed to ingest standard '{standard_type}': {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail=f"Failed to ingest standard: {str(e)}"
        )
