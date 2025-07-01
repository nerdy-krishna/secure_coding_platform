import os
import chromadb
import logging
import traceback
from chromadb.api import ClientAPI

# Configure basic logging to see output in the console
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_test():
    """Attempts to connect to ChromaDB and fetch some data."""
    try:
        # --- 1. Define Connection Settings ---
        host = os.getenv("CHROMA_HOST", "vector_db")
        port = int(os.getenv("CHROMA_PORT", 8000))
        collection_name = "asvs_v5"

        logging.info(f"Attempting to connect to ChromaDB at: http://{host}:{port}")

        # --- 2. Create the Client ---
        # MODIFIED: 'timeout' is a direct argument to HttpClient, not part of Settings.
        client: ClientAPI = chromadb.HttpClient(
            host=host,
            port=port,
        )
        logging.info("Successfully created ChromaDB client object.")

        # --- 3. Check Server Heartbeat ---
        heartbeat = client.heartbeat()
        logging.info(f"Server heartbeat successful. Nanoseconds since epoch: {heartbeat}")

        # --- 4. List Collections ---
        collections = client.list_collections()
        logging.info(f"Available collections: {[c.name for c in collections]}")

        # --- 5. Get the Specific Collection ---
        logging.info(f"Attempting to get collection: '{collection_name}'")
        collection = client.get_collection(name=collection_name)
        logging.info(f"Successfully got collection '{collection.name}'. Count: {collection.count()}")

        # --- 6. Fetch a Sample Item ---
        logging.info("Attempting to fetch 1 item from the collection.")
        sample = collection.get(limit=1, include=["metadatas", "documents"])
        logging.info(f"Successfully fetched sample item: {sample}")

        print("\n" + "="*50)
        print("✅ SUCCESS: All connection and data retrieval steps completed successfully!")
        print("="*50)

    except Exception as e:
        print("\n" + "="*50)
        print("❌ FAILURE: An error occurred during the connection test.")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Details: {e}")
        print("\n--- Full Traceback ---")
        traceback.print_exc()
        print("="*50)

if __name__ == "__main__":
    run_test()