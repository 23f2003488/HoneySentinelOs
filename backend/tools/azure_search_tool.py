import os
import time
import logging
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.search.documents.indexes import SearchIndexClient
from azure.search.documents.indexes.models import SearchIndex, SimpleField, SearchableField

logger = logging.getLogger(__name__)

class AzureSearchTool:
    def __init__(self):
        self.endpoint = os.getenv("AZURE_SEARCH_ENDPOINT")
        self.key = os.getenv("AZURE_SEARCH_ADMIN_KEY")
        self.index_name = os.getenv("AZURE_SEARCH_INDEX_NAME", "repo-code-index")
        
        if self.endpoint and self.key:
            self.credential = AzureKeyCredential(self.key)
            self.client = SearchClient(endpoint=self.endpoint, index_name=self.index_name, credential=self.credential)
            self.index_client = SearchIndexClient(endpoint=self.endpoint, credential=self.credential)
            self.enabled = True
            self._ensure_index_exists()
        else:
            self.enabled = False
            logger.warning("Azure AI Search credentials missing. Semantic search disabled.")

    def _ensure_index_exists(self):
        """Creates the search index if it doesn't exist yet."""
        try:
            # Check if index exists
            self.index_client.get_index(self.index_name)
        except Exception:
            logger.info(f"Creating Azure AI Search Index: {self.index_name}")
            # Define the schema
            fields = [
                SimpleField(name="id", type="Edm.String", key=True),
                SearchableField(name="filepath", type="Edm.String", filterable=True),
                SearchableField(name="content", type="Edm.String")
            ]
            index = SearchIndex(name=self.index_name, fields=fields)
            self.index_client.create_or_update_index(index)
            time.sleep(2) # Give Azure a second to provision it

    def index_codebase(self, files: list[dict]) -> dict:
        """Pushes parsed code files into Azure AI Search."""
        if not self.enabled:
            return {"status": "disabled", "message": "Search not configured"}
            
        try:
            documents = []
            for idx, file_data in enumerate(files):
                content = file_data.get("content", "")
                if not content.strip(): continue
                
                documents.append({
                    "id": str(idx),
                    "filepath": file_data["path"],
                    "content": content[:30000] # Azure limits size per document
                })
            
            if documents:
                self.client.upload_documents(documents=documents)
                logger.info(f"Successfully Indexed {len(documents)} files into Azure AI Search.")
            return {"status": "success", "indexed_count": len(documents)}
        except Exception as e:
            logger.error(f"Failed to index codebase: {e}")
            return {"status": "error", "message": str(e)}

    def search_codebase(self, query: str, top: int = 5) -> dict:
        if not self.enabled:
            return {"error": "Azure Semantic search is not configured."}
        start = time.time()
        try:
            results = self.client.search(search_text=query, top=top)
            matches = [{"file_path": r.get("filepath", "Unknown"), "content_snippet": r.get("content", "")[:1000]} for r in results]
            return {"query": query, "matches_found": len(matches), "results": matches, "duration_ms": int((time.time() - start) * 1000)}
        except Exception as e:
            logger.error(f"Azure Search failed: {e}")
            return {"error": str(e)}