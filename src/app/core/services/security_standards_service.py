import json
import logging
import io
import csv
from typing import List, Dict, Any, Optional, Tuple
import httpx
from fastapi import UploadFile, HTTPException
from app.infrastructure.rag.rag_client import get_rag_service
from app.infrastructure.database.models import CweDetail
from app.infrastructure.database.repositories.rag_job_repo import RAGJobRepository
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from chromadb.utils import embedding_functions

logger = logging.getLogger(__name__)

class SecurityStandardsService:
    """
    Service for parsing authoritative security standards (ASVS, Proactive Controls)
    and ingesting them into the RAG system.
    """

    def __init__(
        self, 
        job_repo: Optional["RAGJobRepository"] = None, 
        llm_config_repo: Optional["LLMConfigRepository"] = None
    ):
        self.rag_service = get_rag_service()
        self.job_repo = job_repo
        self.llm_config_repo = llm_config_repo

    async def _read_file_content(self, file: UploadFile) -> bytes:
        content = await file.read()
        await file.seek(0)
        return content

    def _parse_github_url(self, url: str) -> Tuple[str, str, str, str]:
        """
        Parses a GitHub URL into (owner, repo, branch, path).
        Supports:
        - https://github.com/owner/repo
        - https://github.com/owner/repo/tree/branch/path/to/dir
        """
        clean_url = url.replace("https://github.com/", "")
        parts = clean_url.split("/")
        
        if len(parts) < 2:
            raise ValueError("Invalid GitHub URL. Expected format: owner/repo")
            
        owner = parts[0]
        repo = parts[1]
        branch = "master" # Default
        path = ""
        
        # Check if it's a tree URL
        if len(parts) >= 4 and parts[2] == "tree":
            branch = parts[3]
            if len(parts) > 4:
                path = "/".join(parts[4:])
                
        return owner, repo, branch, path

    async def _fetch_github_files(self, owner: str, repo: str, path: str, branch: str) -> List[Dict[str, Any]]:
        """
        Fetches the file list from GitHub API for a specific path.
        """
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        
        async with httpx.AsyncClient() as client:
            headers = {"User-Agent": "SecureCodingPlatform/1.0"}
            resp = await client.get(api_url, params={"ref": branch}, headers=headers)
            
            if resp.status_code == 404:
                # Fallback: sometimes 'master' is 'main'
                if branch == "master":
                     logger.warning(f"Branch 'master' not found for {owner}/{repo}, trying 'main'")
                     resp = await client.get(api_url, params={"ref": "main"}, headers=headers)
            
            resp.raise_for_status()
            data = resp.json()
            
            if isinstance(data, dict):
                return [data] # Single file
            return data

    async def ingest_asvs_csv(self, file: UploadFile, user_id: int) -> Dict[str, Any]:
        """
        Parses OWASP ASVS 5.0 CSV format and ingests it.
        Expected CSV columns: req_id, req_description, L (levels), chapter_name
        """
        if not self.rag_service:
            raise HTTPException(status_code=503, detail="RAG Service not available")

        content = await self._read_file_content(file)
        text_content = content.decode("utf-8")
        
        documents = []
        metadatas = []
        ids = []
        count = 0

        # ... (parsing logic remains the same, skipping unchanged lines for brevity if possible, 
        # but replace_file_content requires exact match. 
        # I will preserve the parsing logic carefully or Use a larger chunk if I have to re-write it)
        # Actually, I can just replace the method signature and the end block.
        # But this tool requires contiguous block.
        # I'll replace the whole method to be safe and ensure the `user_id` is passed down.
        
        try:
            reader = csv.DictReader(io.StringIO(text_content))
            for row in reader:
                req_id = row.get("ID") or row.get("id") or row.get("req_id")
                description = row.get("Description") or row.get("description") or row.get("req_description")
                
                if not req_id or not description:
                    continue

                # Parse levels
                if "L" in row:
                    try:
                        level_val = int(row["L"])
                        l1 = level_val >= 1
                        l2 = level_val >= 2
                        l3 = level_val >= 3
                    except (ValueError, TypeError):
                        l1, l2, l3 = False, False, False
                else:
                    l1 = bool(row.get("Level 1") or row.get("L1"))
                    l2 = bool(row.get("Level 2") or row.get("L2"))
                    l3 = bool(row.get("Level 3") or row.get("L3"))
                
                cwe = row.get("CWE") or row.get("cwe") or ""
                chapter_name = row.get("Chapter Name") or row.get("Chapter") or row.get("chapter_name") or "General"
                
                # Enriched Content
                doc_text = f"OWASP ASVS {req_id} [{chapter_name}]: {description}"
                if cwe:
                    doc_text += f"\\nRelated CWEs: {cwe}"
                
                metadata = {
                    "source": "OWASP ASVS",
                    "framework_name": "asvs",
                    "control_family": chapter_name,
                    "level_1": l1,
                    "level_2": l2,
                    "level_3": l3,
                    "cwe_ids": str(cwe),
                    "scan_ready": True
                }

                documents.append(doc_text)
                metadatas.append(metadata)
                ids.append(f"asvs-{req_id}")
                count += 1
                
        except Exception as e:
            logger.error(f"Failed to parse ASVS CSV: {e}")
            raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {str(e)}")

        if not documents:
            logger.warning("No documents parsed from ASVS CSV.")
            raise HTTPException(status_code=400, detail="No valid requirements found in CSV. Ensure columns 'ID' and 'Description' exist.")

        self.rag_service.delete_by_framework("asvs")
        self.rag_service.add(documents=documents, metadatas=metadatas, ids=ids)

        # --- BACKFILL JOB RECORD FOR REPROCESSING ---
        if self.job_repo and self.llm_config_repo:
            try:
                # Fetch a default LLM config ID
                configs = await self.llm_config_repo.get_all()
                if configs:
                    default_config_id = configs[0].id
                    file_hash = self.job_repo.hash_content(content)
                    
                    # Create completed job
                    job = await self.job_repo.create_job(
                        user_id=user_id,
                        framework_name="asvs",
                        llm_config_id=default_config_id,
                        file_hash=file_hash,
                    )
                    
                    # Construct processed_documents for future use
                    processed_docs = []
                    for i, doc_text in enumerate(documents):
                        processed_docs.append({
                            "id": ids[i],
                            "original_document": doc_text,
                            "enriched_content": doc_text, # For ASVS, enriched is just the text
                            "metadata": metadatas[i]
                        })
                        
                    await self.job_repo.update_job(job.id, {
                        "raw_content": content,
                        "status": "COMPLETED",
                        "processed_documents": processed_docs,
                        "estimated_cost": {"total_cost": 0.0}, # No LLM cost
                        "actual_cost": 0.0
                    })
                    logger.info(f"Backfilled RAGPreprocessingJob {job.id} for ASVS ingestion.")
                    
            except Exception as e:
                logger.error(f"Failed to backfill job record for ASVS: {e}")

        return {"message": f"Successfully ingested {count} ASVS requirements from CSV.", "count": count}

    async def ingest_proactive_controls_github(self, repo_url: str, user_id: int) -> Dict[str, Any]:
        """
        Fetches OWASP Proactive Controls documents from a GitHub tree URL.
        Target: https://github.com/OWASP/www-project-proactive-controls/tree/master/docs/the-top-10
        Filter: Files starting with 'c' (e.g. c1-define...).
        """
        if not self.rag_service:
            raise HTTPException(status_code=503, detail="RAG Service not available")
            
        try:
            owner, repo, branch, path = self._parse_github_url(repo_url)
            files = await self._fetch_github_files(owner, repo, path, branch)
            
            documents = []
            metadatas = []
            ids = []
            count = 0
            
            async with httpx.AsyncClient() as client:
                for file_node in files:
                    name = file_node["name"].lower()
                    
                    # Filter: Must start with 'c' and end with '.md'
                    # e.g. c1-access-control.md
                    if file_node["type"] == "file" and name.endswith(".md") and name.startswith("c"):
                        
                        raw_url = file_node["download_url"]
                        resp = await client.get(raw_url)
                        content = resp.text
                        
                        doc_text = f"OWASP Proactive Control [{file_node['name']}]:\n{content}"
                        metadata = {
                            "source": "OWASP Proactive Controls",
                            "framework_name": "proactive_controls",
                            "filename": file_node["name"],
                            "scan_ready": False,
                            "url": raw_url
                        }
                        
                        documents.append(doc_text)
                        metadatas.append(metadata)
                        ids.append(f"opc-{file_node['name']}")
                        count += 1
            
            if documents:
                self.rag_service.delete_by_framework("proactive_controls")
                self.rag_service.add(documents=documents, metadatas=metadatas, ids=ids)
                
                # --- BACKFILL JOB RECORD ---
                if self.job_repo and self.llm_config_repo:
                    try:
                        configs = await self.llm_config_repo.get_all()
                        if configs:
                            default_config_id = configs[0].id
                            # For GitHub ingestion, we hash the URL as the "content" or similar unique identifier
                            # effectively acting as version control if URL changes? 
                            # Better: hash the combined content of all files? Too expensive.
                            # Just hash the repo URL + processed count for now to have something unique-ish.
                            file_hash = self.job_repo.hash_content(f"{repo_url}-{count}".encode())
                            
                            job = await self.job_repo.create_job(
                                user_id=user_id,
                                framework_name="proactive_controls",
                                llm_config_id=default_config_id,
                                file_hash=file_hash,
                            )
                            
                            processed_docs = []
                            for i, doc_text in enumerate(documents):
                                processed_docs.append({
                                    "id": ids[i],
                                    "original_document": doc_text,
                                    "enriched_content": doc_text,
                                    "metadata": metadatas[i]
                                })
                                
                            await self.job_repo.update_job(job.id, {
                                "raw_content": repo_url.encode(), # Store URL as raw content
                                "status": "COMPLETED",
                                "processed_documents": processed_docs,
                                "estimated_cost": {"total_cost": 0.0},
                                "actual_cost": 0.0
                            })
                            logger.info(f"Backfilled RAGPreprocessingJob {job.id} for Proactive Controls.")
                    except Exception as e:
                        logger.error(f"Failed to backfill job for Proactive Controls: {e}")

            return {"message": f"Successfully ingested {count} Proactive Controls from {repo_url}", "count": count}

        except Exception as e:
            logger.error(f"Failed to fetch Proactive Controls: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to fetch: {str(e)}")

    async def ingest_cheatsheets_github(self, repo_url: str, user_id: int) -> Dict[str, Any]:
        """
        Fetches OWASP Cheatsheets from a GitHub tree URL.
        Target: https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets
        Filter: All .md files.
        """
        if not self.rag_service:
            raise HTTPException(status_code=503, detail="RAG Service not available")
            
        try:
            owner, repo, branch, path = self._parse_github_url(repo_url)
            files = await self._fetch_github_files(owner, repo, path, branch)
            
            documents = []
            metadatas = []
            ids = []
            count = 0
            
            async with httpx.AsyncClient() as client:
                for idx, file_node in enumerate(files):
                    # Safety limit: Cheatsheet repo is huge.
                    # Start with a reasonable limit to avoid timeout/rate-limits
                    if idx >= 100: 
                        break

                    name = file_node["name"].lower()
                    if file_node["type"] == "file" and name.endswith(".md"):
                        raw_url = file_node["download_url"]
                        resp = await client.get(raw_url)
                        content = resp.text
                        
                        doc_text = f"OWASP Cheatsheet [{file_node['name']}]:\n{content}"
                        metadata = {
                            "source": "OWASP Cheatsheet",
                            "framework_name": "cheatsheets",
                            "filename": file_node["name"],
                            "scan_ready": False,
                            "url": raw_url
                        }
                        
                        documents.append(doc_text)
                        metadatas.append(metadata)
                        ids.append(f"cs-{file_node['name']}")
                        count += 1
            
            if documents:
                self.rag_service.delete_by_framework("cheatsheets")
                self.rag_service.add(documents=documents, metadatas=metadatas, ids=ids)
                
                # --- BACKFILL JOB RECORD ---
                if self.job_repo and self.llm_config_repo:
                    try:
                        configs = await self.llm_config_repo.get_all()
                        if configs:
                            default_config_id = configs[0].id
                            file_hash = self.job_repo.hash_content(f"{repo_url}-{count}".encode())
                            
                            job = await self.job_repo.create_job(
                                user_id=user_id,
                                framework_name="cheatsheets",
                                llm_config_id=default_config_id,
                                file_hash=file_hash,
                            )
                            
                            processed_docs = []
                            for i, doc_text in enumerate(documents):
                                processed_docs.append({
                                    "id": ids[i],
                                    "original_document": doc_text,
                                    "enriched_content": doc_text,
                                    "metadata": metadatas[i]
                                })
                                
                            await self.job_repo.update_job(job.id, {
                                "raw_content": repo_url.encode(),
                                "status": "COMPLETED",
                                "processed_documents": processed_docs,
                                "estimated_cost": {"total_cost": 0.0},
                                "actual_cost": 0.0
                            })
                            logger.info(f"Backfilled RAGPreprocessingJob {job.id} for Cheatsheets.")
                    except Exception as e:
                        logger.error(f"Failed to backfill job for Cheatsheets: {e}")
                
            return {"message": f"Successfully ingested {count} Cheatsheets from {repo_url}", "count": count}

        except Exception as e:
            logger.error(f"Failed to fetch Cheatsheets: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to fetch: {str(e)}")
