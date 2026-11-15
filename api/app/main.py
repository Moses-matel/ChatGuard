from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.config import settings
from app.db import init_db
from app.rate_limit import RateLimiterMiddleware
from app.routes import check


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db(settings.db_path)
    yield


app = FastAPI(
    title="ChatGuard Reputation API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(RateLimiterMiddleware)
app.include_router(check.router)


@app.get("/health")
async def health():
    return {"status": "ok"}

