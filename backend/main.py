import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import router

app = FastAPI(title="LLM Firewall API", version="1.0.0", description="Explainable prompt-injection and sensitive-data scanner")
allowed_origins = ["http://localhost:5173", "http://127.0.0.1:5173"]
frontend_origin = os.getenv("FRONTEND_ORIGIN", "").strip()
if frontend_origin and frontend_origin not in allowed_origins:
    allowed_origins.append(frontend_origin)

app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.include_router(router)
