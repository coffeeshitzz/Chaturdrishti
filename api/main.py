import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from loguru import logger

from api.routes.analyze import router as analyze_router
from api.routes.graph import router as graph_router
from api.routes.health import router as health_router

app = FastAPI(
    title="ChaturDrishti API",
    description="Adversarial Reasoning Engine for OSINT Exposure Analysis",
    version="0.1.0"
)

# Allow React frontend to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000","http://localhost:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(analyze_router, tags=["Analysis"])
app.include_router(graph_router, tags=["Graph"])
app.include_router(health_router, tags=["Health"])


@app.on_event("startup")
async def startup():
    logger.info("🚀 ChaturDrishti API starting up...")
    logger.info("   Docs available at: http://localhost:8000/docs")


@app.on_event("shutdown")
async def shutdown():
    logger.info("ChaturDrishti API shutting down...")