import asyncio
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.getcwd(), 'src'))

from unittest.mock import MagicMock, AsyncMock
from app.core.services.security_standards_service import SecurityStandardsService
from fastapi import UploadFile

async def test_ingestion():
    csv_content = """chapter_id,chapter_name,section_id,section_name,req_id,req_description,L
V1,Encoding and Sanitization,V1.1,Encoding and Sanitization Architecture,V1.1.1,"Verify that input is decoded...",2"""
    
    mock_file = MagicMock(spec=UploadFile)
    mock_file.read = AsyncMock(return_value=csv_content.encode('utf-8'))
    mock_file.seek = AsyncMock()
    
    print("Initializing Service...")
    try:
        service = SecurityStandardsService()
        # Mock rag_service to avoid actual DB calls and dependency issues if Chroma is down
        service.rag_service = MagicMock()
        service.rag_service.delete_by_framework = MagicMock()
        service.rag_service.add = MagicMock()
        
        print("Testing Ingestion...")
        result = await service.ingest_asvs_csv(mock_file)
        print("Result:", result)
        
        # Verify call args
        if service.rag_service.add.called:
            call_args = service.rag_service.add.call_args
            # kwargs are used in the actual call: add(documents=..., metadatas=..., ids=...)
            kwargs = call_args.kwargs
            docs = kwargs.get('documents')
            metas = kwargs.get('metadatas')
            
            print(f"Documents ingested: {len(docs)}")
            print("First doc metadata:", metas[0])
            
            # Check if levels are correct
            meta = metas[0]
            if meta['level_1'] is True and meta['level_2'] is True:
                 print("SUCCESS: Level logic worked (L=2 implies L1=True, L2=True)")
            elif meta['level_2'] is True:
                 print("SUCCESS: Level 2 captured.")
            else:
                 print("FAILURE: Levels not captured correctly.")

        else:
            print("FAILURE: No documents were added to RAG service.")
            
    except Exception as e:
        print(f"Error during test: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_ingestion())
