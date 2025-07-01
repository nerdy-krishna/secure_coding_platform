# src/app/infrastructure/rag/rag_client.py
import chromadb
import os
import logging
from typing import List, Dict, Any, Optional  # Ensure Optional is imported
from chromadb.api import ClientAPI  # Corrected import path

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
    _initialization_attempted = False
    _initialization_succeeded = False
    client: Optional[ClientAPI] = (
        None  # Instance attribute, changed type hint to Optional
    )
    asvs_collection = (
        None  # Instance attribute, will be chromadb.api.models.Collection.Collection
    )

    def __new__(cls):
        if cls._instance is not None:  # Successfully initialized before
            return cls._instance

        if cls._initialization_attempted and not cls._initialization_succeeded:
            # Previous attempt failed, don't try again.
            logger.warning(
                "RAGService initialization previously failed. Not re-attempting connection."
            )
            raise ConnectionError(
                "RAGService initialization previously failed and will not be re-attempted."
            )

        # This is the first actual attempt to initialize
        cls._initialization_attempted = True

        try:
            # Log this only on the first actual attempt
            logger.info(
                f"Attempting to connect to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT} (first attempt for RAGService singleton)"
            )

            # Create the actual instance object that will be stored in _instance
            instance = super().__new__(cls)

            instance.client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
            instance.client.heartbeat()  # Heartbeat check
            logger.info("Successfully connected to ChromaDB.")

            instance.asvs_collection = instance.client.get_or_create_collection(
                name=ASVS_COLLECTION_NAME
            )
            logger.info(f"Collection '{ASVS_COLLECTION_NAME}' loaded/created.")

            cls._instance = instance
            cls._initialization_succeeded = True
            return cls._instance

        except Exception as e:
            cls._initialization_succeeded = False  # Explicitly mark as failed
            logger.critical(
                f"Failed to initialize RAGService or connect to ChromaDB on first attempt: {e}",
                exc_info=True,  # Log with full traceback for the initial failure
            )
            # cls._instance remains None
            raise  # Re-raise the exception; get_rag_service will handle it by returning None

    def query_asvs(
        self, query_texts: List[str], n_results: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Queries the ASVS collection for relevant security guidelines.
        """
        # This check is important. If RAGService instance exists but asvs_collection is somehow None
        # (though current logic should prevent this if initialization succeeds),
        # this prevents an AttributeError.
        if not hasattr(self, "asvs_collection") or self.asvs_collection is None:
            logger.error(
                "ASVS collection is not available. RAGService might not have initialized correctly."
            )
            return []
        # Actual query logic would go here. For now, returning empty list to satisfy Pylance.
        # Example:
        # results = self.asvs_collection.query(query_texts=query_texts, n_results=n_results)
        # return results.get("documents", []) if results else []
        return []  # Ensures all paths return List[Dict[str, Any]]


def get_rag_service() -> Optional[RAGService]:  # Changed return type hint
    """
    Factory function to get the singleton instance of RAGService.
    """
    try:
        return RAGService()
    except Exception:
        # The RAGService constructor will log the critical error.
        # This allows the caller to handle the failure gracefully.
        return None
