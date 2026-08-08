from typing import Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text
from database.db import get_db

router = APIRouter(prefix="/api/health", tags=["Health & Status"])

@router.get("", response_model=Dict[str, Any])
def get_health_status(db: Session = Depends(get_db)):
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        print(f"[Vigilo Health Check Error]: {e}")
        db_status = "error"

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "pipeline": "operational",
        "version": "2.5"
    }
