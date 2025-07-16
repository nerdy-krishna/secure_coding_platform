import chromadb
import os
import logging
import socket
import requests
from typing import List, Dict, Any, Optional
from chromadb.api import ClientAPI
from chromadb.api.types import Where
from chromadb.utils import embedding_functions

logger = logging.getLogger(__name__)

CHROMA_HOST = os.getenv("CHROMA_HOST", "vector_db")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", 8000))
ASVS_COLLECTION_NAME = "asvs_v5"
MODEL_NAME = "all-MiniLM-L6-v2"


def test_connection(host: str, port: int) -> bool:
    """Test basic network connectivity to ChromaDB."""
    try:
        # Test socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            logger.info(f"✓ Socket connection to {host}:{port} successful")
            
            # Test HTTP endpoint
            try:
                response = requests.get(f"http://{host}:{port}/api/v1/heartbeat", timeout=10)
                logger.info(f"✓ HTTP heartbeat response: {response.status_code}")
                return True
            except requests.exceptions.RequestException as e:
                logger.warning(f"⚠ Socket connection OK, but HTTP failed: {e}")
                return False
        else:
            logger.error(f"✗ Cannot connect to {host}:{port} - Connection refused")
            return False
            
    except socket.gaierror as e:
        logger.error(f"✗ DNS resolution failed for {host}: {e}")
        return False
    except Exception as e:
        logger.error(f"✗ Connection test failed: {e}")
        return False


class RAGService:
    """A service for interacting with the ChromaDB vector store."""
    _client: Optional[ClientAPI] = None
    _asvs_collection: Optional[Any] = None

    def __init__(self):
        """Initializes the RAGService, raising an exception on failure."""
        try:
            logger.info(f"RAGService attempting to connect to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT}")
            
            # Test basic connectivity first
            if not test_connection(CHROMA_HOST, CHROMA_PORT):
                raise ConnectionError(f"Cannot establish basic connection to {CHROMA_HOST}:{CHROMA_PORT}")
            
            # Create ChromaDB client with proper settings for v0.5.3
            client = chromadb.HttpClient(
                host=CHROMA_HOST,
                port=CHROMA_PORT,
                ssl=False,
                headers={"Connection": "keep-alive"}
            )
            
            logger.info("Testing ChromaDB heartbeat...")
            heartbeat_result = client.heartbeat()
            logger.info(f"✓ ChromaDB heartbeat successful: {heartbeat_result}")
            
            # Define the embedding function, same as in the ingestion script
            embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name=MODEL_NAME
            )
            
            logger.info(f"Getting or creating collection: {ASVS_COLLECTION_NAME}")
            collection = client.get_or_create_collection(
                name=ASVS_COLLECTION_NAME, embedding_function=embedding_function  # type: ignore
            )
            logger.info(f"✓ Collection '{ASVS_COLLECTION_NAME}' ready")
            
            # Test collection accessibility
            try:
                collection_count = collection.count()
                logger.info(f"✓ Collection contains {collection_count} documents")
            except Exception as e:
                logger.warning(f"⚠ Could not get collection count: {e}")
            
            self._client = client
            self._asvs_collection = collection

            logger.info(f"✓ RAGService fully initialized and collection '{ASVS_COLLECTION_NAME}' loaded.")
            
        except Exception as e:
            logger.critical(f"CRITICAL: Failed to initialize RAGService. Error details:")
            logger.critical(f"  Host: {CHROMA_HOST}")
            logger.critical(f"  Port: {CHROMA_PORT}")
            logger.critical(f"  Error: {str(e)}")
            logger.critical(f"  Error type: {type(e).__name__}")
            
            # Additional debugging info
            logger.critical("Environment variables:")
            for key, value in os.environ.items():
                if 'CHROMA' in key.upper():
                    logger.critical(f"  {key}={value}")
            
            self._client = None
            self._asvs_collection = None
            raise

    def add(
        self, documents: List[str], metadatas: List[Dict[str, Any]], ids: List[str]
    ):
        """Adds documents to the collection."""
        if not self._asvs_collection:
            raise ConnectionError("ChromaDB collection is not available.")
        self._asvs_collection.add(
            documents=documents, metadatas=metadatas, ids=ids
        )

    def get_by_framework(self, framework_name: str) -> Dict[str, Any]:
        """Retrieves all documents for a given framework using a metadata filter."""
        if not self._asvs_collection:
            raise ConnectionError("ChromaDB collection is not available.")

        # Use a 'where' filter to efficiently query ChromaDB for documents
        # with the matching framework_name in their metadata.
        where_filter: Where = {"framework_name": {"$eq": framework_name}}

        return self._asvs_collection.get(
            where=where_filter, include=["metadatas", "documents"]
        )

    def delete_by_framework(self, framework_name: str) -> int:
        """Deletes all documents associated with a specific framework."""
        if not self._asvs_collection:
            raise ConnectionError("ChromaDB collection is not available.")

        # Get all document IDs for the framework first
        docs_to_delete = self.get_by_framework(framework_name)
        ids_to_delete = docs_to_delete.get("ids", [])

        if not ids_to_delete:
            logger.info(f"No documents found for framework '{framework_name}' to delete.")
            return 0

        self.delete(ids=ids_to_delete)
        logger.info(f"Deleted {len(ids_to_delete)} documents for framework '{framework_name}'.")
        return len(ids_to_delete)

    def delete(self, ids: List[str]):
        """Deletes documents from the collection by their IDs."""
        if not self._asvs_collection:
            raise ConnectionError("ChromaDB collection is not available.")
        self._asvs_collection.delete(ids=ids)

    def query_asvs(self, query_texts: List[str], n_results: int = 5, where: Optional[Where] = None) -> Dict[str, Any]:
        """Queries the ASVS collection."""
        if not self._asvs_collection:
            logger.error("ASVS collection is not available.")
            raise ConnectionError("ASVS collection not available in RAGService.")
        
        try:
            logger.debug(f"Querying collection with {len(query_texts)} queries, n_results={n_results}")
            results = self._asvs_collection.query(
                query_texts=query_texts, 
                n_results=n_results,
                where=where
            )
            logger.debug(f"Query successful, returned {len(results.get('ids', []))} result sets")
            return results
        except Exception as e:
            logger.error(f"Failed to query ChromaDB collection '{ASVS_COLLECTION_NAME}': {e}", exc_info=True)
            raise


_rag_instance: Optional[RAGService] = None

def get_rag_service() -> Optional[RAGService]:
    """Factory function to get the singleton instance of RAGService."""
    global _rag_instance
    if _rag_instance is None:
        try:
            _rag_instance = RAGService()
        except Exception as e:
            logger.error(f"Failed to create RAGService instance: {e}")
            _rag_instance = None
            return None
    return _rag_instance