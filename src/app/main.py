# src/app/main.py

import logging
import os
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware

# Import our new routers from the api module
from app.api.endpoints import router as api_router, llm_router

# --- Authentication Imports ---
from app.auth.core import fastapi_users
from app.auth.backend import auth_backend
from app.auth.schemas import UserRead, UserCreate, UserUpdate

# Import the centralized settings object for CORS configuration

logger = logging.getLogger(__name__)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Handles application startup and shutdown events.
    The init_db() call has been removed, as database schema is now
    managed exclusively by Alembic migrations.
    """
    logger.info("Application startup.")
    yield
    logger.info("Application shutdown.")


app = FastAPI(
    title="Secure Coding Platform API",
    version="0.1.0",
    description="API for the Secure Coding Platform, providing analysis, generation, and GRC features.",
    lifespan=lifespan,
)

# --- CORS Middleware Configuration ---
# This is crucial for frontend interaction, especially with credentials (cookies).
allowed_origins_str = os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
)
origins = [
    origin.strip() for origin in allowed_origins_str.split(",") if origin.strip()
]

if not origins:
    origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
    logger.warning(
        f"ALLOWED_ORIGINS environment variable not set or empty. Defaulting to: {origins}"
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    # --- START: CORRECTED LINE ---
    # Cannot use ["*"] when allow_credentials is True. Must be an explicit list.
    allow_headers=["Content-Type", "Authorization"],
    # --- END: CORRECTED LINE ---
)
logger.info(f"CORS middleware configured for origins: {origins}")


# --- Custom Exception Handler for 422 Errors ---
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Catches Pydantic validation errors and provides detailed logging."""
    logger.error(
        "Pydantic Validation Error",
        extra={"errors": exc.errors(), "url": str(request.url)},
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=jsonable_encoder({"detail": exc.errors()}),
    )


# --- Include API Routers ---

# Main application router for submissions and results
app.include_router(api_router, prefix="/api/v1", tags=["Submissions"])

# NEW: Router for managing LLM Configurations
app.include_router(
    llm_router, prefix="/api/v1/admin", tags=["Admin: LLM Configurations"]
)


# --- Include FastAPI Users Authentication Routers ---
app.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

app.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

app.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate),
    prefix="/api/v1/users",
    tags=["Users"],
)


# --- Root Endpoint ---
@app.get("/", tags=["Root"])
async def read_root():
    """A simple root endpoint to confirm the API is running."""
    return {"message": "Welcome to the 5th Secure Coding Platform API!"}
