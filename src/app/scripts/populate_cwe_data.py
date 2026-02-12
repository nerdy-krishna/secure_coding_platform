import csv
import asyncio
import logging
import re
import os
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.dialects.postgresql import insert
# Add imports for ChromaDB types
from chromadb.types import Metadata
from typing import List, Dict, Any

from app.config.config import settings
from app.infrastructure.database.models import CweDetail, CweOwaspMapping
from app.infrastructure.rag.rag_client import get_rag_service

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Name for the new ChromaDB collection for semantic search
CWE_RAG_COLLECTION_NAME = "cwe_collection"
CSV_FILE_PATH = 'src/app/shared/data/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv'

async def main():
    """
    Main function to load the ASVS CSV and ingest it into the SQL and RAG databases.
    """
    logging.info("Starting ASVS data ingestion process...")

    # 1. Load the CSV data
    cwe_detail_objects = []
    cwe_owasp_mapping_objects = []
    
    if not os.path.exists(CSV_FILE_PATH):
        logging.error(f"Error: '{CSV_FILE_PATH}' not found. Please ensure the file exists.")
        return

    try:
        with open(CSV_FILE_PATH, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            logging.info(f"Successfully opened CSV file: {CSV_FILE_PATH}")
            
            for row in reader:
                # row keys: chapter_id, chapter_name, section_id, section_name, req_id, req_description, L
                
                req_id = row['req_id']
                description = row['req_description']
                chapter_name = row['chapter_name']
                section_name = row['section_name']
                level = row['L']
                chapter_id = row['chapter_id']
                
                # Construct RAG document text
                rag_text = (
                    f"ASVS Requirement {req_id}\n"
                    f"Chapter: {chapter_name}\n"
                    f"Section: {section_name}\n"
                    f"Description: {description}\n"
                    f"Level: {level}"
                )
                
                # Prepare CweDetail object (Mapping ASVS Req -> CweDetail)
                cwe_detail_objects.append({
                    "id": req_id,
                    "name": f"{chapter_name} - {section_name}",
                    "abstraction": f"ASVS Level {level}",
                    "description": description,
                    "rag_document_text": rag_text
                })
                
                # Prepare CweOwaspMapping object
                # Extract numeric rank from chapter_id (e.g., "V1" -> 1)
                rank_match = re.search(r'V(\d+)', chapter_id)
                rank = int(rank_match.group(1)) if rank_match else 99

                cwe_owasp_mapping_objects.append({
                    "cwe_id": req_id,
                    "owasp_category_id": chapter_id,
                    "owasp_category_name": chapter_name,
                    "owasp_rank": rank
                })
                
        logging.info(f"Parsed {len(cwe_detail_objects)} ASVS records from CSV.")

    except Exception as e:
        logging.error(f"Error reading or parsing CSV: {e}")
        return

    # 2. Populate the SQL Database
    if not settings.ASYNC_DATABASE_URL:
        raise ValueError("ASYNC_DATABASE_URL is not set!")

    engine = create_async_engine(settings.ASYNC_DATABASE_URL)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    try:
        async with session_factory() as session:
            async with session.begin():
                # Use INSERT ... ON CONFLICT DO UPDATE to ensure latest data
                # For CweDetail
                if cwe_detail_objects:
                    logging.info(f"Ingesting {len(cwe_detail_objects)} records into 'cwe_details' table...")
                    stmt_details = insert(CweDetail).values(cwe_detail_objects)
                    # Update fields if ID exists
                    stmt_details = stmt_details.on_conflict_do_update(
                        index_elements=['id'],
                        set_={
                            "name": stmt_details.excluded.name,
                            "abstraction": stmt_details.excluded.abstraction,
                            "description": stmt_details.excluded.description,
                            "rag_document_text": stmt_details.excluded.rag_document_text
                        }
                    )
                    await session.execute(stmt_details)
                
                # For CweOwaspMapping
                if cwe_owasp_mapping_objects:
                    logging.info(f"Ingesting {len(cwe_owasp_mapping_objects)} records into 'cwe_owasp_mappings' table...")
                    stmt_mappings = insert(CweOwaspMapping).values(cwe_owasp_mapping_objects)
                    stmt_mappings = stmt_mappings.on_conflict_do_update(
                        index_elements=['cwe_id'],
                        set_={
                            "owasp_category_id": stmt_mappings.excluded.owasp_category_id,
                            "owasp_category_name": stmt_mappings.excluded.owasp_category_name,
                            "owasp_rank": stmt_mappings.excluded.owasp_rank
                        }
                    )
                    await session.execute(stmt_mappings)

            logging.info("✅ SQL database ingestion complete.")
    except Exception as e:
        logging.error(f"A database error occurred during SQL ingestion: {e}", exc_info=True)
        return

    # 3. Ingest into the RAG (Vector) Database
    logging.info("Initializing RAG service for ChromaDB ingestion...")
    rag_service = get_rag_service()
    if not rag_service:
        logging.error("Could not initialize RAG service. Aborting ChromaDB ingestion.")
        return
        
    try:
        # Get or create collection
        # Note: We might want to delete existing collection if structure changed significantly, 
        # but for now we append/update.
        collection = rag_service._client.get_or_create_collection(name=CWE_RAG_COLLECTION_NAME) # type: ignore
        
        # Prepare data for ChromaDB
        ids: List[str] = []
        documents: List[str] = []
        metadatas: List[Metadata] = []

        for item in cwe_detail_objects:
            ids.append(item['id'])
            documents.append(item['rag_document_text'])
            
            # Create a dictionary that strictly adheres to the Metadata type
            meta_item: Metadata = {
                "cwe_id": item['id'],
                "name": item['name'],
                "abstraction": item.get('abstraction') or "N/A"
            }
            metadatas.append(meta_item)

        # Ingest in batches
        batch_size = 200
        logging.info(f"Ingesting {len(ids)} documents into ChromaDB collection '{CWE_RAG_COLLECTION_NAME}'...")
        for i in range(0, len(ids), batch_size):
            batch_ids = ids[i:i+batch_size]
            batch_docs = documents[i:i+batch_size]
            batch_metadatas = metadatas[i:i+batch_size]
            collection.add(ids=batch_ids, documents=batch_docs, metadatas=batch_metadatas)
            logging.info(f"  - Ingested batch {i//batch_size + 1}...")

        logging.info("✅ RAG (ChromaDB) ingestion complete.")
    except Exception as e:
        logging.error(f"An error occurred during RAG ingestion: {e}", exc_info=True)
        return

if __name__ == "__main__":
    asyncio.run(main())