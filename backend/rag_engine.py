"""RAG Engine for semantic search using Qdrant and local embeddings."""
import os
from langchain_community.document_loaders import TextLoader, JSONLoader
from langchain_google_genai import GoogleGenerativeAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_qdrant import QdrantVectorStore
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

QDRANT_HOST = os.environ.get("QDRANT_HOST", "localhost")
QDRANT_PORT = int(os.environ.get("QDRANT_PORT", "6333"))
COLLECTION_NAME = "soc_knowledge"

# Initialize cloud embedding model (avoids downloading 5GB PyTorch locally)
embeddings = GoogleGenerativeAIEmbeddings(model="models/embedding-001")

def get_qdrant_client():
    try:
        client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT, timeout=1.0)
        # Verify connectivity
        client.get_collections()
        return client
    except Exception:
        logger.info("Qdrant server not running/reachable. Falling back to local storage.")
        db_path = os.path.join(os.path.dirname(__file__), "qdrant_local")
        return QdrantClient(path=db_path)

def init_qdrant():
    client = get_qdrant_client()
    if not client.collection_exists(COLLECTION_NAME):
        client.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=768, distance=Distance.COSINE),
        )
        logger.info(f"Created Qdrant collection: {COLLECTION_NAME}")

def ingest_text_document(text: str, metadata: dict = None):
    """Chunks a text document and ingests it into Qdrant."""
    init_qdrant()
    client = get_qdrant_client()
    
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,
        chunk_overlap=200,
        add_start_index=True,
    )
    
    # Create LangChain Document objects manually
    from langchain_core.documents import Document
    docs = [Document(page_content=text, metadata=metadata or {})]
    
    splits = text_splitter.split_documents(docs)
    
    qdrant = QdrantVectorStore(
        client=client,
        collection_name=COLLECTION_NAME,
        embedding=embeddings,
    )
    qdrant.add_documents(splits)
    logger.info(f"Ingested {len(splits)} chunks into Qdrant.")
    return len(splits)

def search_knowledge(query: str, top_k: int = 3):
    """Search the Qdrant collection for relevant documents."""
    client = get_qdrant_client()
    if not client.collection_exists(COLLECTION_NAME):
        return []
        
    qdrant = QdrantVectorStore(
        client=client,
        collection_name=COLLECTION_NAME,
        embedding=embeddings,
    )
    
    results = qdrant.similarity_search(query, k=top_k)
    return results


def ingest_pdf_bytes(pdf_bytes: bytes, filename: str) -> int:
    """Extracts text from PDF bytes using pypdf, chunks it, and ingests into Qdrant."""
    import io
    import pypdf
    
    # Read PDF text
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    text_content = []
    for page_num, page in enumerate(reader.pages):
        page_text = page.extract_text()
        if page_text:
            text_content.append(page_text)
            
    full_text = "\n\n".join(text_content)
    if not full_text.strip():
        logger.warning(f"No text extracted from PDF: {filename}")
        return 0
        
    metadata = {
        "title": filename,
        "source": "pdf_upload",
        "page_count": len(reader.pages)
    }
    
    return ingest_text_document(full_text, metadata)

def ingest_analyst_feedback(alert_id: int, attack_type: str, analyst_notes: str, verdict: str):
    """
    Continuous Learning Loop: Ingest analyst feedback on an alert directly into the RAG database.
    This allows the AI to learn from False Positives and True Positives over time.
    """
    feedback_text = (
        f"Analyst Feedback on {attack_type} Alert #{alert_id}:\n"
        f"Verdict: {verdict}\n"
        f"Analyst Notes: {analyst_notes}\n"
        f"Rule of Thumb: If similar patterns occur, this is likely a {verdict}."
    )
    
    metadata = {
        "source": "analyst_feedback",
        "alert_id": alert_id,
        "attack_type": attack_type,
        "verdict": verdict,
        "title": f"Feedback: {attack_type} -> {verdict}"
    }
    
    logger.info(f"Ingesting analyst feedback for Alert {alert_id} into continuous learning loop.")
    return ingest_text_document(feedback_text, metadata)
