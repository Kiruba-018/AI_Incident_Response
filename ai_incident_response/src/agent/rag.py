"""RAG implementation for SOC policy retrieval."""
from pathlib import Path

import asyncio
from langchain_chroma import Chroma
from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter

BASE_DIR = Path(__file__).resolve().parents[2]


client = Chroma(
    collection_name = "Soc_Policies",
    persist_directory=str(BASE_DIR / "chroma_db")
)

# Load documents into the vector store if empty
if client._collection.count()==0:
    loader = PyPDFLoader(file_path= str(BASE_DIR / "static" / "soc_policy" / "SOC_Port_Scanning_Policy.pdf")).load()


    splitter = RecursiveCharacterTextSplitter(
        chunk_size = 400,
        chunk_overlap = 100
    )

    documents = splitter.split_documents(loader)
    client.add_documents(documents)


async def retrieve_soc_policy(query: str) -> str:
    """Retrieve relevant SOC policy documents based on the query.
    
    Args - query (str): The query string to search for relevant documents. Returns - str: Concatenated content of the top relevant documents.
    """
    results = client.similarity_search(query, k=3)
    return "\n".join([doc.page_content for doc in results])