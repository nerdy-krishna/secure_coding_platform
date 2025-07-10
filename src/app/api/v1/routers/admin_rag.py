# src/app/api/v1/routers/admin_rag.py
import logging
import uuid
import pandas as pd
import io
from typing import Any, Dict, List, cast
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status

from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database import models as db_models
from app.infrastructure.rag.rag_client import get_rag_service, RAGService
from app.api.v1.models import RAGDocumentDeleteRequest

logger = logging.getLogger(__name__)
rag_router = APIRouter(prefix="/rag", tags=["Admin: RAG Management"])


@rag_router.post("/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_documents(
    framework_name: str = Form(...),
    file: UploadFile = File(...),
    user: db_models.User = Depends(current_superuser),
    rag_service: RAGService = Depends(get_rag_service),
):
    """
    Ingests documents from an uploaded CSV file into the RAG knowledge base
    for a specific framework.
    """
    if not file.filename or not file.filename.endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="A CSV file with a valid filename is required."
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
        # All other columns are treated as metadata
        metadatas_raw = df.drop(columns=["id", "document"]).to_dict("records")
        metadatas = cast(List[Dict[str, Any]], metadatas_raw)

        # Add the framework name to each metadata entry
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