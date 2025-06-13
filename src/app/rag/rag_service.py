# src/app/rag/rag_service.py
import chromadb
import os
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Configuration for ChromaDB
# Set the default host to the docker-compose service name
CHROMA_HOST = os.getenv("CHROMA_HOST", "vector_db") 
# Corrected default port to 8000, which is ChromaDB's default internal port.
CHROMA_PORT = int(os.getenv("CHROMA_PORT", 8000)) 

ASVS_COLLECTION_NAME = "asvs_collection"

class RAGService:
    """
    A singleton service for interacting with the ChromaDB vector store.
    """
    _instance = None
    client: chromadb.HttpClient = None
    
    def __new__(cls):
        if cls._instance is None:
            try:
                cls._instance = super().__new__(cls)
                logger.info(f"Attempting to connect to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT}")
                cls._instance.client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
                # Heartbeat check to confirm connection before proceeding
                cls._instance.client.heartbeat()
                logger.info("Successfully connected to ChromaDB.")
                
                # Ensure the collection exists
                cls._instance.asvs_collection = cls._instance.client.get_or_create_collection(name=ASVS_COLLECTION_NAME)
                logger.info(f"Collection '{ASVS_COLLECTION_NAME}' loaded/created.")

            except Exception as e:
                logger.critical(f"Failed to initialize RAGService or connect to ChromaDB: {e}", exc_info=True)
                cls._instance = None
                raise
        return cls._instance

    def query_asvs(self, query_texts: List[str], n_results: int = 5) -> List[Dict[str, Any]]:
        """
        Queries the ASVS collection for relevant security guidelines.
        """
        if not self.asvs_collection:
            logger.error("ASVS collection is not available.")
            return []
            
        try:
            results = self.asvs_collection.query(
                query_texts=query_texts,
                n_results=n_results,
            )
            
            # Reformat results to be more useful
            formatted_results = []
            if results and results.get('documents'):
                for i, docs in enumerate(results['documents']):
                    query_result = { "query": query_texts[i], "results": [] }
                    for j, doc in enumerate(docs):
                        query_result["results"].append({
                            "document": doc,
                            "distance": results['distances'][i][j] if results.get('distances') else None,
                            "metadata": results['metadatas'][i][j] if results.get('metadatas') else None,
                        })
                    formatted_results.append(query_result)
            return formatted_results
        except Exception as e:
            logger.error(f"Error querying ChromaDB: {e}", exc_info=True)
            return []


def get_rag_service() -> RAGService:
    """
    Factory function to get the singleton instance of RAGService.
    """
    try:
        return RAGService()
    except Exception:
        # The RAGService constructor will log the critical error.
        # This allows the caller to handle the failure gracefully.
        return None