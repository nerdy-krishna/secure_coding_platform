# src/app/rag/rag_service.py
import os
import logging
from typing import List, Dict, Any

import chromadb

# Configure logging
logger = logging.getLogger(__name__)

class RAGService:
    """
    A service to interact with the ChromaDB RAG knowledge base.
    """
    def __init__(self):
        """
        Initializes the RAGService by connecting to the ChromaDB client.
        """
        try:
            # For services running inside Docker talking to other Docker services,
            # we use the service name as the host.
            CHROMA_HOST = os.getenv("CHROMADB_HOST", "vector_db") 
            CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
            
            self.client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
            self.asvs_collection = self.client.get_collection(name="asvs_v5")
            
            logger.info("RAGService initialized and connected to ChromaDB collection 'asvs_v5'.")

        except Exception as e:
            logger.error(f"Failed to initialize RAGService or connect to ChromaDB: {e}", exc_info=True)
            self.client = None
            self.asvs_collection = None

    def query_asvs(self, query_texts: List[str], n_results: int = 10) -> List[str]:
        """
        Queries the ASVS collection for security requirements relevant to the query texts.

        Args:
            query_texts: A list of strings to search for (e.g., ["password policy", "SQL injection"]).
            n_results: The number of results to return for each query text.

        Returns:
            A flat, deduplicated list of the most relevant requirement document strings.
            Returns an empty list if the service failed to initialize or the query fails.
        """
        if not self.asvs_collection:
            logger.error("Cannot query ASVS: RAGService is not properly initialized.")
            return []

        try:
            # We only need the document text for the agent's context
            results = self.asvs_collection.query(
                query_texts=query_texts,
                n_results=n_results,
                include=["documents"] 
            )
            
            documents = results.get('documents')
            if not documents:
                return []

            # The query returns a list of lists, one list per query_text.
            # We need to flatten this into a single list.
            flat_docs = [doc for sublist in documents for doc in sublist]
            
            # Return a list of unique documents, preserving order.
            unique_docs = list(dict.fromkeys(flat_docs))
            
            logger.info(f"Successfully queried and returned {len(unique_docs)} unique requirements for: {query_texts}")
            return unique_docs

        except Exception as e:
            logger.error(f"An error occurred during ASVS query: {e}", exc_info=True)
            return []

# Singleton instance to be used by other parts of the application
rag_service_instance = RAGService()

def get_rag_service() -> RAGService:
    """
    Returns the singleton instance of the RAGService.
    """
    return rag_service_instance