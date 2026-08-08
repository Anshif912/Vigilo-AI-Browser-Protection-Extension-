from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database.db import init_db
from routers.analyze import router as analyze_router
from routers.threats import router as threats_router
from routers.campaigns import router as campaigns_router
from routers.stats import router as stats_router
from routers.health import router as health_router

app = FastAPI(
    title="Vigilo Threat Intelligence API",
    description="Real-Time AI Browser Protection & Cyber Threat Intelligence Engine API",
    version="2.5.0"
)

# Enable CORS for Extension & SOC Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(analyze_router)
app.include_router(threats_router)
app.include_router(campaigns_router)
app.include_router(stats_router)
app.include_router(health_router)

@app.on_event("startup")
def on_startup():
    init_db()
    print("[Vigilo] Threat Intelligence Enhancement Engine active & ready.")

@app.get("/")
def root():
    return {
        "service": "Vigilo Threat Intelligence Platform API",
        "status": "Online",
        "version": "2.5.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
