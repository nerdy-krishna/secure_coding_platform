# src/app/api/v1/routers/admin_rag.py
import logging
import uuid
import io
from typing import Any, Dict, List, cast
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

from app.api.v1.dependencies import (
    get_llm_config_repository,
    get_rag_job_repository,
    get_rag_preprocessor_service,
)
from app.core.schemas import (
    EnrichedDocument,
    PreprocessingResponse,
    RAGJobStartResponse,
    RAGJobStatusResponse,
)
from app.core.services.rag_preprocessor_service import RAGPreprocessorService
from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.rag_job_repo import RAGJobRepository
from app.infrastructure.rag.rag_client import get_rag_service, RAGService
from app.api.v1.models import RAGDocumentDeleteRequest

logger = logging.getLogger(__name__)
rag_router = APIRouter(prefix="/rag", tags=["Admin: RAG Management"])


# --- NEW Pre-processing Workflow Endpoints ---


@rag_router.post("/preprocess/start", response_model=RAGJobStartResponse)
async def start_preprocessing_job(
    file: UploadFile = File(...),
    llm_config_id: uuid.UUID = Form(...),
    framework_name: str = Form(...),
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

    # Check if a completed job with the same content and LLM config exists.
    existing_job = await job_repo.find_completed_job_by_hash(file_hash, llm_config_id)

    if existing_job and existing_job.estimated_cost and existing_job.processed_documents:
        # If a duplicate exists, create a NEW job record...
        job = await job_repo.create_job(
            user_id=user.id,
            framework_name=framework_name,
            llm_config_id=llm_config_id,
            file_hash=file_hash,
        )
        # ...then immediately update it with the old job's data and a PENDING_APPROVAL status.
        await job_repo.update_job(job.id, {
            "status": "PENDING_APPROVAL",
            "estimated_cost": existing_job.estimated_cost,
            "actual_cost": existing_job.actual_cost,
            "processed_documents": existing_job.processed_documents,
            "raw_content": contents
        })
        message = "An identical file has been processed before. You can approve to re-use the result or cancel."
    else:
        # If it's a new file, create a job and calculate the cost.
        job = await job_repo.create_job(
            user_id=user.id,
            framework_name=framework_name,
            llm_config_id=llm_config_id,
            file_hash=file_hash,
        )
        await job_repo.update_job(job.id, {"raw_content": contents})
        estimated_cost = await preprocessor.estimate_cost(contents, llm_config_id)
        await job_repo.update_job(
            job.id, {"status": "PENDING_APPROVAL", "estimated_cost": estimated_cost}
        )
        message = "Cost estimated. Please approve to start processing."

    final_job_state = await job_repo.get_job_by_id(job.id, user.id)
    if not final_job_state:
        raise HTTPException(status_code=500, detail="Failed to retrieve job state after creation.")

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
            status_code=400, detail=f"Job is not awaiting approval. Status: {job.status}"
        )

    # If the job already has processed documents (from a duplicate run), we can complete it immediately.
    if job.processed_documents:
        await job_repo.update_job(job_id, {"status": "COMPLETED"})
        return {"message": "Existing job result approved. You can now ingest the data."}

    raw_content = job.raw_content
    if not raw_content:
        await job_repo.update_job(job_id, {"status": "FAILED", "error_message": "Original file content is missing."})
        raise HTTPException(
            status_code=400, detail="Cannot process job, original file content is missing."
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

    processed_docs = None
    if job.processed_documents:
        processed_docs = [EnrichedDocument(**doc) for doc in job.processed_documents]

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
):
    """
    Deletes all existing documents for a framework and ingests the new,
    processed documents. This is the final step after a job is complete.
    """
    try:
        framework_name = payload.framework_name
        documents = payload.processed_documents

        rag_service.delete_by_framework(framework_name)

        ids = [doc.id for doc in documents]
        docs_to_add = [doc.enriched_content for doc in documents]
        metadatas = [doc.metadata for doc in documents]

        for meta in metadatas:
            meta["framework_name"] = framework_name

        rag_service.add(documents=docs_to_add, metadatas=metadatas, ids=ids)

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

        rag_service.add(documents=documents, metadatas=metadatas, ids=ids)
        return {
            "message": f"Successfully ingested {len(documents)} documents for framework '{framework_name}'."
        }

    except Exception as e:
        logger.error(f"Failed to ingest documents for {framework_name}: {e}", exc_info=True)
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