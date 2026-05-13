import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from fastapi import APIRouter
from api.models import HealthResponse
from graph.ingestion import Neo4jConnection
import ollama

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health():
    """Check health of all system components."""

    # Check Neo4j
    neo4j_status = "ok"
    try:
        with Neo4jConnection() as conn:
            conn.run("RETURN 1")
    except Exception:
        neo4j_status = "unavailable"

    # Check Ollama
    ollama_status = "ok"
    try:
        ollama.chat(
            model="llama3.1:8b",
            messages=[{"role": "user", "content": "ping"}],
            options={"num_predict": 1}
        )
    except Exception:
        ollama_status = "unavailable"

    overall = "healthy" if all(
        s == "ok" for s in [neo4j_status, ollama_status]
    ) else "degraded"

    return HealthResponse(
        status=overall,
        neo4j=neo4j_status,
        ollama=ollama_status
    )