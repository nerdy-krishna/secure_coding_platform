# src/app/core/services/rag_preprocessor_service.py
import asyncio
import io
import logging
import uuid
import re
from typing import Any, Dict, List, Tuple, Optional

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


class CodePattern(BaseModel):
    language: str = Field(
        description="The programming language (e.g., 'python', 'java', 'generic')."
    )
    vulnerable_code: str = Field(description="Example of vulnerable code usage.")
    secure_code: str = Field(description="Example of secure code patterns.")


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
    code_patterns: List[CodePattern] = Field(
        default_factory=list,
        description="A list of code examples for requested languages.",
    )


class RAGPreprocessorService:
    """A service to enrich raw framework documents using an LLM."""

    def __init__(
        self, job_repo: RAGJobRepository, llm_config_repo: LLMConfigRepository
    ):
        self.job_repo = job_repo
        self.llm_config_repo = llm_config_repo

    def _create_enrichment_prompt(
        self, document_text: str, metadata: Dict[str, Any], target_languages: List[str]
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

        langs_str = (
            ", ".join(target_languages) if target_languages else "Generic examples only"
        )

        return f"""
You are a Principal Security Architect. Your task is to take a security control and rewrite it to be more explicit for another AI model to use as a guideline for finding vulnerabilities.

{context_str}Transform the following security control into these parts:
1.  **security_rule**: A concise, clear statement of the security principle.
2.  **vulnerability_pattern**: A generic description of the anti-pattern.
3.  **secure_pattern**: A generic description of the secure implementation.
4.  **code_patterns**: Provide a vulnerable and secure code example for each of the following languages: [{langs_str}].
    - If a language is NOT relevant for this specific control (e.g., SQL Injection for CSS), do NOT generate code for it.
    - Always include a 'Generic' pattern if applicable.

SECURITY CONTROL:
"{document_text}"

Respond ONLY with a valid JSON object conforming to the schema. Do not include any other text.
"""

    def _parse_patterns_from_string(self, content: str) -> Dict[str, CodePattern]:
        """
        Attempts to recover structured CodePatterns from a legacy enriched string.
        """
        patterns = {}
        # Regex to find language blocks
        block_regex = re.compile(
            r"\[\[(\w+) PATTERNS\]\].*?Vulnerable:\s*```\s*\n(.*?)\n\s*```.*?Secure:\s*```\s*\n(.*?)\n\s*```",
            re.DOTALL | re.IGNORECASE,
        )

        matches = block_regex.findall(content)
        for lang, vuln, secure in matches:
            lang_key = lang.lower()
            patterns[lang_key] = CodePattern(
                language=lang_key,
                vulnerable_code=vuln.strip(),
                secure_code=secure.strip(),
            )

        return patterns

    def _format_enriched_content(
        self, base_content: str, patterns: Dict[str, CodePattern]
    ) -> str:
        """
        Reconstructs the full enriched content string from base content and structured patterns.
        """
        sorted_langs = sorted(patterns.keys())
        patterns_str = ""
        for lang in sorted_langs:
            cp = patterns[lang]
            # Handle if cp is dict or object
            if isinstance(cp, dict):
                cp = CodePattern(**cp)

            lang_upper = cp.language.upper()
            patterns_str += (
                f"\n\n[[{lang_upper} PATTERNS]]\n"
                f"Vulnerable:\n```\n{cp.vulnerable_code}\n```\n"
                f"Secure:\n```\n{cp.secure_code}\n```"
            )

        return base_content + patterns_str

    def _clean_base_content(self, full_content: str) -> str:
        """
        Removes pattern blocks from the full content to get just the security rules.
        """
        match = re.search(r"\[\[\w+ PATTERNS\]\]", full_content)
        if match:
            return full_content[: match.start()].strip()
        return full_content.strip()

    async def _enrich_document(
        self,
        llm_client: LLMClient,
        doc_id: str,
        doc_text: str,
        metadata: Dict[str, Any],
        target_languages: List[str],
    ) -> Tuple[EnrichedDocument, float]:
        """Processes a single document row through the LLM."""

        prompt = self._create_enrichment_prompt(doc_text, metadata, target_languages)

        response = await llm_client.generate_structured_output(
            prompt, EnrichedContentResponse
        )

        cost = response.cost or 0.0

        parsed_patterns = {}
        base_content = doc_text  # fallback

        if response.parsed_output and isinstance(
            response.parsed_output, EnrichedContentResponse
        ):
            out = response.parsed_output
            base_content = (
                f"**Security Rule:** {out.security_rule}\n\n"
                f"**Vulnerability Pattern (Description):** {out.vulnerability_pattern}\n\n"
                f"**Secure Pattern (Description):** {out.secure_pattern}"
            )

            if out.code_patterns:
                for cp in out.code_patterns:
                    parsed_patterns[cp.language.lower()] = cp

            # metadata["languages"] will be set by caller after merge

        metadata["patterns"] = {k: v.model_dump() for k, v in parsed_patterns.items()}

        # Temporary string construction for this specific result
        full_content = self._format_enriched_content(base_content, parsed_patterns)

        enriched_doc = EnrichedDocument(
            id=doc_id,
            original_document=doc_text,
            enriched_content=full_content,
            metadata=metadata,
        )
        return enriched_doc, cost

    async def estimate_cost(
        self,
        csv_content: bytes,
        llm_config_id: uuid.UUID,
        target_languages: List[str] = [],
        previous_job_state: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Parses a CSV and estimates the total cost of processing."""
        llm_config = await self.llm_config_repo.get_by_id_with_decrypted_key(
            llm_config_id
        )
        if not llm_config:
            raise ValueError("LLM Configuration not found for cost estimation.")

        try:
            df = self._parse_csv(csv_content)
        except ValueError:
            # If content is not a valid CSV (e.g. it's a URL for Proactive Controls),
            # we can't estimate cost based on rows.
            # For now, return 0 cost or handle differently.
            logger.warning("Content is not a valid CSV, skipping token estimation.")
            return {
                "total_cost": 0.0,
                "input_tokens": 0,
                "output_tokens": 0,
                "target_languages": target_languages,
            }

        # Build map of existing patterns if available
        existing_map = {}
        if previous_job_state and previous_job_state.processed_documents:
            for doc in previous_job_state.processed_documents:
                doc_id = str(doc.get("id"))
                existing_map[doc_id] = doc

        total_input_tokens = 0
        target_languages = [t.lower() for t in target_languages]

        for _, row in df.iterrows():
            metadata = row.drop(["id", "document"]).to_dict()
            doc_id = str(row["id"])
            doc_text = str(row["document"])

            langs_to_generate = target_languages

            if doc_id in existing_map:
                existing_doc = existing_map[doc_id]
                existing_patterns = {}

                if (
                    "metadata" in existing_doc
                    and "patterns" in existing_doc["metadata"]
                ):
                    existing_patterns = existing_doc["metadata"]["patterns"]
                elif "enriched_content" in existing_doc:
                    parsed = self._parse_patterns_from_string(
                        existing_doc["enriched_content"]
                    )
                    existing_patterns = {k: v.model_dump() for k, v in parsed.items()}

                langs_to_generate = [
                    lang for lang in target_languages if lang not in existing_patterns
                ]

            # If nothing new to generate, cost is 0 for this row
            if not langs_to_generate and doc_id in existing_map:
                continue

            prompt = self._create_enrichment_prompt(
                doc_text, metadata, langs_to_generate
            )

            # FIX: Use decrypted_api_key
            total_input_tokens += await count_tokens(
                prompt,
                llm_config,
                api_key=getattr(llm_config, "decrypted_api_key", None),
            )

        estimation = estimate_cost_for_prompt(llm_config, total_input_tokens)
        estimation["target_languages"] = target_languages
        return estimation

    def _parse_csv(self, csv_content: bytes) -> pd.DataFrame:
        """Parses CSV content and validates required columns."""
        try:
            # Handle potential encoding issues
            try:
                df = pd.read_csv(io.BytesIO(csv_content))
            except UnicodeDecodeError:
                df = pd.read_csv(io.BytesIO(csv_content), encoding="latin1")

            # Standardize column names (case-insensitive)
            df.columns = df.columns.str.strip()

            # Map common variations to 'id' and 'document'
            column_mapping = {
                "ID": "id",
                "req_id": "id",
                "Description": "document",
                "description": "document",
                "req_description": "document",
            }
            df.rename(columns=column_mapping, inplace=True)

            if "id" not in df.columns or "document" not in df.columns:
                raise ValueError(
                    "CSV must contain 'id' and 'document' columns (or compatible aliases like 'ID', 'Description')."
                )

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

        target_languages = []
        if job.estimated_cost and "target_languages" in job.estimated_cost:
            target_languages = job.estimated_cost["target_languages"]

        target_languages = [t.lower() for t in target_languages]

        llm_client = await get_llm_client(job.llm_config_id)
        if not llm_client:
            await self.job_repo.update_job(
                job_id, {"status": "FAILED", "error_message": "LLM client init failed."}
            )
            return

        # Fetch PREVIOUS job for merging
        previous_job = await self.job_repo.get_latest_job_for_framework(
            job.framework_name, user_id
        )
        previous_map = {}

        # Use previous job if it's not the current one (completed)
        if (
            previous_job
            and str(previous_job.id) != str(job.id)
            and previous_job.processed_documents
        ):
            logger.info(
                f"Found previous job {previous_job.id} for framework {job.framework_name} with {len(previous_job.processed_documents)} docs."
            )
            for doc in previous_job.processed_documents:
                previous_map[str(doc.get("id"))] = doc
        else:
            logger.info(
                "No previous completed job found for merging (or it was the same ID)."
            )

        df = self._parse_csv(csv_content)
        tasks = []
        doc_processing_meta = {}

        async def enrich_with_semaphore(
            doc_id: str,
            doc_text: str,
            metadata: Dict[str, Any],
            langs_for_this_doc: List[str],
        ):
            async with CONCURRENCY_SEMAPHORE:
                return await self._enrich_document(
                    llm_client, doc_id, doc_text, metadata, langs_for_this_doc
                )

        for _, row in df.iterrows():
            doc_id = str(row["id"])
            doc_text = str(row["document"])
            metadata = row.drop(["id", "document"]).to_dict()

            existing_doc = previous_map.get(doc_id)
            existing_patterns = {}

            if existing_doc:
                if (
                    "metadata" in existing_doc
                    and "patterns" in existing_doc["metadata"]
                ):
                    existing_patterns = existing_doc["metadata"]["patterns"]
                    logger.debug(
                        f"Doc {doc_id}: Found existing structured patterns for: {list(existing_patterns.keys())}"
                    )
                elif "enriched_content" in existing_doc:
                    parsed = self._parse_patterns_from_string(
                        existing_doc["enriched_content"]
                    )
                    existing_patterns = {k: v.model_dump() for k, v in parsed.items()}
                    logger.debug(
                        f"Doc {doc_id}: Parsed existing patterns from string for: {list(existing_patterns.keys())}"
                    )

            doc_processing_meta[doc_id] = {
                "existing_patterns": existing_patterns,
                "original_doc": existing_doc,
            }

            langs_to_generate = [
                lang for lang in target_languages if lang not in existing_patterns
            ]

            if not langs_to_generate and existing_doc:
                # Optimized skip
                logger.debug(
                    f"Doc {doc_id}: No new languages to generate. Skipping LLM."
                )
                tasks.append(self._dummy_result(existing_doc))
            else:
                logger.debug(f"Doc {doc_id}: Generating languages: {langs_to_generate}")
                tasks.append(
                    enrich_with_semaphore(doc_id, doc_text, metadata, langs_to_generate)
                )

        processed_results_with_costs = await asyncio.gather(
            *tasks, return_exceptions=True
        )

        successful_docs: List[EnrichedDocument] = []
        errors = []
        total_cost = 0.0

        for res in processed_results_with_costs:
            if isinstance(res, Exception):
                logger.error(f"Task failed: {res}")
                errors.append(res)
                continue

            if isinstance(res, dict):
                # Skipped doc (existing)
                try:
                    d_meta = res.get("metadata", {})
                    doc_id = str(res.get("id"))
                    meta_info = doc_processing_meta.get(doc_id)
                    if meta_info and meta_info["existing_patterns"]:
                        d_meta["patterns"] = meta_info["existing_patterns"]

                    doc_obj = EnrichedDocument(
                        id=str(res.get("id")),
                        original_document=str(res.get("original_document", "")),
                        enriched_content=str(res.get("enriched_content", "")),
                        metadata=d_meta,
                    )
                    successful_docs.append(doc_obj)
                except Exception as e:
                    logger.error(f"Error restoring existing doc {res.get('id')}: {e}")
                    errors.append(e)
                continue

            elif isinstance(res, tuple):
                # New enrichment
                doc, cost = res
                total_cost += cost

                doc_id = doc.id
                meta_info = doc_processing_meta.get(doc_id)

                # MERGE DEBUGGING
                clean_base = self._clean_base_content(doc.enriched_content)
                new_patterns_dict = doc.metadata.get("patterns", {})
                existing_patterns_dict = {}
                if meta_info:
                    existing_patterns_dict = meta_info["existing_patterns"]

                final_patterns = {**existing_patterns_dict, **new_patterns_dict}

                logger.info(
                    f"Doc {doc_id}: Merged Existing {list(existing_patterns_dict.keys())} + New {list(new_patterns_dict.keys())} -> Final {list(final_patterns.keys())}"
                )

                patterns_objs = {}
                for lang, p_data in final_patterns.items():
                    if isinstance(p_data, dict):
                        patterns_objs[lang] = CodePattern(**p_data)
                    else:
                        patterns_objs[lang] = p_data

                final_content = self._format_enriched_content(clean_base, patterns_objs)

                doc.enriched_content = final_content
                doc.metadata["patterns"] = {
                    k: v.model_dump() for k, v in patterns_objs.items()
                }
                doc.metadata["languages"] = list(patterns_objs.keys())

                successful_docs.append(doc)

        if errors:
            await self.job_repo.update_job(
                job_id,
                {
                    "status": "FAILED",
                    "error_message": f"Encountered {len(errors)} errors during enrichment. First error: {str(errors[0])}",
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

    async def _dummy_result(self, doc_dict: Dict[str, Any]):
        return doc_dict

    async def preprocess_csv(
        self, csv_content: bytes, llm_config_id: uuid.UUID
    ) -> List[EnrichedDocument]:
        """Legacy compatibility method."""
        # Minimal impl fallback
        llm_client = await get_llm_client(llm_config_id)
        if not llm_client:
            raise ValueError("Failed to initialize LLM Client.")
        try:
            df = pd.read_csv(io.BytesIO(csv_content))
        except Exception:
            return []

        tasks = []
        for _, row in df.iterrows():
            doc_id = str(row["id"])
            doc_text = str(row["document"])
            metadata = row.drop(["id", "document"]).to_dict()
            tasks.append(
                self._enrich_document(llm_client, doc_id, doc_text, metadata, [])
            )
        processed_docs = await asyncio.gather(*tasks, return_exceptions=True)
        final = []
        for res in processed_docs:
            if isinstance(res, tuple):
                final.append(res[0])
        return final
