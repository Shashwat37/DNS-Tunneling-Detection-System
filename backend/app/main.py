from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.db import close_db
from app.routers import auth, uploads, results

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await close_db()


app = FastAPI(
    title="DNS Tunneling Detection System",
    version=settings.app_version,
    description="API for detecting DNS tunneling in uploaded query logs",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        # Vercel deployments
        "https://dns-tunneling-detection-system-8wtvzwakz-shashwat8.vercel.app",
        "https://dns-tunneling-detection-system.vercel.app",
    ],
    allow_origin_regex=r"https://dns-tunneling-detection-system-.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth.router)
app.include_router(uploads.router)
app.include_router(results.router)


# ---------------------------------------------------------------------------
# Core routes
# ---------------------------------------------------------------------------

@app.get("/health", tags=["system"])
async def health_check():
    return {
        "status": "ok",
        "version": settings.app_version,
        "environment": settings.app_env,
    }


@app.get("/", include_in_schema=False)
async def root():
    return {"message": "DTDS API — see /docs for interactive API docs"}
