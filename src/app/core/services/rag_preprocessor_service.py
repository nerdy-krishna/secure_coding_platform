# src/app/core/services/rag_preprocessor_service.py
import asyncio
import io
import logging
import uuid
from typing import Any, Dict, List, Tuple

import pandas as pd
from pydantic import BaseModel, Field

from app.core.schemas import EnrichedDocument
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.rag_job_repo import RAGJobRepository
from app.infrastructure.llm_client import LLMClient, get_llm_client
from app.shared.lib.cost_estimation import count_tokens, estimate_cost_for_prompt

logger = logging.getLogger(__name__)

# Concurrency limit for LLM calls
CONCURRENCY_SEMAPHORE = asyncio.Semaphore(10)


class EnrichedContentResponse(BaseModel):
    """The required structured output from the LLM for each row."""

    security_rule: str = Field(
        description="A concise, clear statement of the security principle or rule."
    )
    vulnerability_pattern: str = Field(
        description="An explicit description of the anti-pattern or vulnerability that occurs when this rule is broken."
    )
    secure_pattern: str = Field(
        description="A description of the correct code pattern or implementation for this rule."
    )


class RAGPreprocessorService:
    """A service to enrich raw framework documents using an LLM."""

    def __init__(
        self, job_repo: RAGJobRepository, llm_config_repo: LLMConfigRepository
    ):
        self.job_repo = job_repo
        self.llm_config_repo = llm_config_repo

    def _create_enrichment_prompt(
        self, document_text: str, metadata: Dict[str, Any]
    ) -> str:
        """Creates the prompt for the LLM to enrich a single document."""

        # Dynamically build a context string from available metadata
        context_parts = []
        if "control_family" in metadata:
            context_parts.append(f"Control Family: {metadata['control_family']}")
        if "control_title" in metadata:
            context_parts.append(f"Control Title: {metadata['control_title']}")

        context_str = "\n".join(context_parts)
        if context_str:
            context_str = f"ADDITIONAL CONTEXT:\n{context_str}\n\n"

        return f"""
You are a Principal Security Architect. Your task is to take a security control and rewrite it to be more explicit for another AI model to use as a guideline for finding vulnerabilities.

{context_str}Transform the following security control into three distinct parts:
1.  **security_rule**: A concise, clear statement of the security principle.
2.  **vulnerability_pattern**: A description of the anti-pattern or vulnerability to look for in code that violates this rule.
3.  **secure_pattern**: A description of the correct code pattern or secure implementation of this rule.

SECURITY CONTROL:
"{document_text}"

Respond ONLY with a valid JSON object conforming to the schema. Do not include any other text or explanation.
"""

    async def _enrich_document(
        self, llm_client: LLMClient, doc_id: str, doc_text: str, metadata: Dict[str, Any]
    ) -> Tuple[EnrichedDocument, float]:
        """Processes a single document row through the LLM."""
        prompt = self._create_enrichment_prompt(doc_text, metadata)
        response = await llm_client.generate_structured_output(
            prompt, EnrichedContentResponse
        )

        enriched_content_str = ""
        if response.parsed_output and isinstance(
            response.parsed_output, EnrichedContentResponse
        ):
            enriched_content_str = (
                f"**Security Rule:** {response.parsed_output.security_rule}\n\n"
                f"**Vulnerability Pattern (What to look for):** {response.parsed_output.vulnerability_pattern}\n\n"
                f"**Secure Pattern (What to enforce):** {response.parsed_output.secure_pattern}"
            )
        else:
            logger.warning(
                f"Failed to enrich document {doc_id}. Using original text. Error: {response.error}"
            )
            enriched_content_str = doc_text

        enriched_doc = EnrichedDocument(
            id=doc_id,
            original_document=doc_text,
            enriched_content=enriched_content_str,
            metadata=metadata,
        )
        return enriched_doc, response.cost or 0.0

    async def estimate_cost(
        self, csv_content: bytes, llm_config_id: uuid.UUID
    ) -> Dict[str, Any]:
        """Parses a CSV and estimates the total cost of processing."""
        llm_config = await self.llm_config_repo.get_by_id_with_decrypted_key(
            llm_config_id
        )
        if not llm_config:
            raise ValueError("LLM Configuration not found for cost estimation.")

        df = self._parse_csv(csv_content)
        total_input_tokens = 0
        for _, row in df.iterrows():
            metadata = row.drop(["id", "document"]).to_dict()
            prompt = self._create_enrichment_prompt(str(row["document"]), metadata)
            total_input_tokens += await count_tokens(
                prompt, llm_config, llm_config.decrypted_api_key
            )

        return estimate_cost_for_prompt(llm_config, total_input_tokens)

    def _parse_csv(self, csv_content: bytes) -> pd.DataFrame:
        """Parses CSV content and validates required columns."""
        try:
            df = pd.read_csv(io.BytesIO(csv_content))
            if "id" not in df.columns or "document" not in df.columns:
                raise ValueError("CSV must contain 'id' and 'document' columns.")
            return df
        except Exception as e:
            logger.error(f"Failed to parse CSV content: {e}")
            raise ValueError(f"Invalid CSV file: {e}")

    async def run_preprocessing_job(
        self, job_id: uuid.UUID, user_id: int, csv_content: bytes
    ):
        """
        The main background task for running a job after approval.
        """
        job = await self.job_repo.get_job_by_id(job_id, user_id=user_id)
        if not job or not job.llm_config_id:
            logger.error(f"Job {job_id} or its LLM config not found for processing.")
            return

        llm_client = await get_llm_client(job.llm_config_id)
        if not llm_client:
            await self.job_repo.update_job(
                job_id, {"status": "FAILED", "error_message": "LLM client init failed."}
            )
            return

        df = self._parse_csv(csv_content)
        tasks = []

        # Helper coroutine to wrap the enrichment call with a semaphore.
        # This avoids the late-binding closure issue by taking arguments explicitly.
        async def enrich_with_semaphore(doc_id: str, doc_text: str, metadata: Dict[str, Any]):
            async with CONCURRENCY_SEMAPHORE:
                return await self._enrich_document(
                    llm_client, doc_id, doc_text, metadata
                )

        for _, row in df.iterrows():
            doc_id = str(row["id"])
            doc_text = str(row["document"])
            metadata = row.drop(["id", "document"]).to_dict()

            async def process_with_semaphore(d_id: str, d_text: str, m_data: dict):
                async with CONCURRENCY_SEMAPHORE:
                    return await self._enrich_document(
                        llm_client, d_id, d_text, m_data
                    )

            tasks.append(process_with_semaphore(doc_id, doc_text, metadata))

        processed_results_with_costs = await asyncio.gather(*tasks, return_exceptions=True)

        successful_docs: List[EnrichedDocument] = []
        errors = []
        total_cost = 0.0

        for res in processed_results_with_costs:
            if isinstance(res, Exception):
                errors.append(res)
            elif isinstance(res, tuple):
                doc, cost = res
                successful_docs.append(doc)
                total_cost += cost

        if errors:
            await self.job_repo.update_job(
                job_id,
                {
                    "status": "FAILED",
                    "error_message": f"Encountered {len(errors)} errors during enrichment.",
                },
            )
            return

        await self.job_repo.update_job(
            job_id,
            {
                "status": "COMPLETED",
                "processed_documents": [doc.model_dump() for doc in successful_docs],
                "actual_cost": total_cost,
                "completed_at": pd.Timestamp.utcnow().to_pydatetime(),
            },
        )

    async def preprocess_csv(
        self, csv_content: bytes, llm_config_id: uuid.UUID
    ) -> List[EnrichedDocument]:
        """
        Parses a CSV file and enriches each document using an LLM.

        Returns:
            A list of enriched document objects.
        """
        llm_client = await get_llm_client(llm_config_id)
        if not llm_client:
            raise ValueError("Failed to initialize LLM Client for pre-processing.")

        try:
            df = pd.read_csv(io.BytesIO(csv_content))
            if "id" not in df.columns or "document" not in df.columns:
                raise ValueError("CSV must contain 'id' and 'document' columns.")
        except Exception as e:
            logger.error(f"Failed to parse CSV content: {e}")
            raise ValueError(f"Invalid CSV file: {e}")

        tasks = []
        for _, row in df.iterrows():
            doc_id = str(row["id"])
            doc_text = str(row["document"])
            metadata = row.drop(["id", "document"]).to_dict()
            tasks.append(
                self._enrich_document(llm_client, doc_id, doc_text, metadata)
            )

        processed_docs = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out any exceptions that may have occurred
        successful_results = [
            doc for doc in processed_docs if isinstance(doc, EnrichedDocument)
        ]
        errors = [res for res in processed_docs if isinstance(res, Exception)]
        if errors:
            logger.error(f"Encountered {len(errors)} errors during document enrichment.")

        return successful_results