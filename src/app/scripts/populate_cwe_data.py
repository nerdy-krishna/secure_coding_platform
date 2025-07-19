import json
import asyncio
import logging
import re
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.dialects.postgresql import insert
# Add imports for ChromaDB types
from chromadb.types import Metadata
from typing import List

from app.config.config import settings
from app.infrastructure.database.models import CweDetail, CweOwaspMapping
from app.infrastructure.rag.rag_client import get_rag_service

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Name for the new ChromaDB collection for semantic search
CWE_RAG_COLLECTION_NAME = "cwe_collection"

async def main():
    """
    Main function to load the processed JSON and ingest it into the SQL and RAG databases.
    """
    logging.info("Starting data ingestion process...")

    # 1. Load the processed JSON data
    try:
        with open('src/app/cwe_data_with_owasp.json', 'r', encoding='utf-8') as f:
            cwe_data = json.load(f)
        logging.info(f"Successfully loaded {len(cwe_data)} CWE records from JSON file.")
    except FileNotFoundError:
        logging.error("Error: 'cwe_data_with_owasp.json' not found. Please run the processing script first.")
        return
    except json.JSONDecodeError:
        logging.error("Error: Could not decode JSON. The file might be corrupt.")
        return

    # 2. Populate the SQL Database
    if not settings.ASYNC_DATABASE_URL:
        raise ValueError("ASYNC_DATABASE_URL is not set!")

    engine = create_async_engine(settings.ASYNC_DATABASE_URL)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    cwe_detail_objects = []
    cwe_owasp_mapping_objects = []

    for item in cwe_data:
        cwe_detail_objects.append({
            "id": item['cwe_id'],
            "name": item['name'],
            "abstraction": item.get('abstraction'),
            "description": item['description'],
            "rag_document_text": item['rag_document_text']
        })
        
        if 'owasp_category_id' in item:
            # Extract the rank number from the category ID (e.g., "A01" -> 1)
            rank_match = re.search(r'A(\d{2})', item['owasp_category_id'])
            rank = int(rank_match.group(1)) if rank_match else 99

            cwe_owasp_mapping_objects.append({
                "cwe_id": item['cwe_id'],
                "owasp_category_id": item['owasp_category_id'],
                "owasp_category_name": item['owasp_category_name'],
                "owasp_rank": rank
            })

    try:
        async with session_factory() as session:
            async with session.begin():
                # Use INSERT ... ON CONFLICT DO NOTHING to prevent errors on re-runs
                # For CweDetail
                if cwe_detail_objects:
                    logging.info(f"Ingesting {len(cwe_detail_objects)} records into 'cwe_details' table...")
                    stmt_details = insert(CweDetail).values(cwe_detail_objects)
                    stmt_details = stmt_details.on_conflict_do_nothing(index_elements=['id'])
                    await session.execute(stmt_details)
                
                # For CweOwaspMapping
                if cwe_owasp_mapping_objects:
                    logging.info(f"Ingesting {len(cwe_owasp_mapping_objects)} records into 'cwe_owasp_mappings' table...")
                    stmt_mappings = insert(CweOwaspMapping).values(cwe_owasp_mapping_objects)
                    stmt_mappings = stmt_mappings.on_conflict_do_nothing(index_elements=['cwe_id'])
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
        collection = rag_service._client.get_or_create_collection(name=CWE_RAG_COLLECTION_NAME) # type: ignore
        
        # Prepare data for ChromaDB with explicit typing
        ids: List[str] = []
        documents: List[str] = []
        metadatas: List[Metadata] = []

        for item in cwe_data:
            ids.append(item['cwe_id'])
            documents.append(item['rag_document_text'])
            
            # Create a dictionary that strictly adheres to the Metadata type
            meta_item: Metadata = {
                "cwe_id": item['cwe_id'],
                "name": item['name'],
                # Ensure the value is a string, not None
                "abstraction": item.get('abstraction') or "N/A"
            }
            metadatas.append(meta_item)

        # Ingest in batches to avoid overwhelming the client
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