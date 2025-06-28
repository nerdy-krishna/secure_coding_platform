# src/app/main.py

import logging
import logging.config
import os
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from psycopg.errors import DuplicateColumn
from starlette.responses import JSONResponse

# Import our new routers from the api module
from app.api.endpoints import router as api_router, llm_router
from app.auth.backend import auth_backend
from app.auth.core import fastapi_users
from app.auth.schemas import UserCreate, UserRead, UserUpdate
from app.core.config import settings
# --- New Logging Imports ---
from app.core.logging_config import LOGGING_CONFIG, correlation_id_var
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

# Apply the logging configuration right at the start
logging.config.dictConfig(LOGGING_CONFIG)

# Get the logger for this module
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # This code runs on application startup
    logger.info("Application startup...")
    
    if settings.ASYNC_DATABASE_URL:
        logger.info("Setting up database checkpointer tables...")
        try:
            # FIX: Convert the SQLAlchemy URL to a standard psycopg/asyncpg URL
            conn_str = settings.ASYNC_DATABASE_URL.replace("postgresql+asyncpg", "postgresql")
            
            async with AsyncPostgresSaver.from_conn_string(conn_str) as checkpointer:
                await checkpointer.setup()
            logger.info("Checkpointer tables setup complete.")
        except DuplicateColumn as e:
            logger.info(
                f"Checkpointer tables already exist, which is expected. Details: {e}. Continuing..."
            )
        except Exception as e:
            logger.error(f"Failed to setup checkpointer tables on startup: {e}", exc_info=True)
    else:
        logger.warning("Database URL not set, skipping checkpointer setup.")
    
    yield
    # This code runs on shutdown
    logger.info("Application shutdown.")

app = FastAPI(
    title="Secure Coding Platform API",
    version="0.1.0",
    description="API for the Secure Coding Platform, providing analysis, generation, and GRC features.",
    lifespan=lifespan,
)

# --- START: New Correlation ID Middleware ---
@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    # Check for an existing correlation ID in the header, or create a new one
    corr_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    
    # Set the ID in the context variable so our logger can access it
    correlation_id_var.set(corr_id)
    
    # Process the request
    response = await call_next(request)
    
    # Add the correlation ID to the response headers
    response.headers["X-Correlation-ID"] = corr_id
    
    logger.info(f"Request to {request.url.path} completed with status {response.status_code}")
    return response
# --- END: New Correlation ID Middleware ---


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
    allow_headers=["Content-Type", "Authorization"],
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