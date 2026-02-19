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

from app.api.v1.routers.projects import router as projects_router
from app.api.v1.routers.admin import llm_router
from app.api.v1.routers.admin_frameworks import framework_router
from app.api.v1.routers.admin_agents import agent_router
from app.api.v1.routers.admin_prompts import prompt_router
from app.api.v1.routers.admin_rag import rag_router
from app.api.v1.routers.admin_logs import router as logs_router
from app.api.v1.routers.chat import router as chat_router
from app.api.v1.routers.refresh import router as refresh_router
from app.api.v1.routers.setup import router as setup_router
from app.api.v1.routers.admin_config import router as admin_config_router
from app.api.v1.routers.llm_config import router as admin_llm_config_router
from app.infrastructure.auth.backend import auth_backend
from app.infrastructure.auth.core import fastapi_users
from app.infrastructure.auth.schemas import UserCreate, UserRead, UserUpdate
from app.config.config import settings
from app.infrastructure.llm_client_rate_limiter import initialize_rate_limiters
from app.config.logging_config import LOGGING_CONFIG, correlation_id_var
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

# Apply the logging configuration right at the start
logging.config.dictConfig(LOGGING_CONFIG)
logging.captureWarnings(True)

# Get the logger for this module
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # This code runs on application startup
    logger.info("Application startup...")

    # Initialize global rate limiters for LLM providers
    initialize_rate_limiters()

    if settings.ASYNC_DATABASE_URL:
        logger.info("Setting up database checkpointer tables...")
        try:
            # FIX: Convert the SQLAlchemy URL to a standard psycopg/asyncpg URL
            conn_str = settings.ASYNC_DATABASE_URL.replace(
                "postgresql+asyncpg", "postgresql"
            )

            async with AsyncPostgresSaver.from_conn_string(conn_str) as checkpointer:
                await checkpointer.setup()
            logger.info("Checkpointer tables setup complete.")
        except DuplicateColumn as e:
            logger.info(
                f"Checkpointer tables already exist, which is expected. Details: {e}. Continuing..."
            )
        except Exception as e:
            logger.error(
                f"Failed to setup checkpointer tables on startup: {e}", exc_info=True
            )
    else:
        logger.warning("Database URL not set, skipping checkpointer setup.")

    # --- Initialize System Configuration Cache ---
    from app.core.config_cache import SystemConfigCache
    from app.infrastructure.database.database import AsyncSessionLocal
    from app.infrastructure.database.repositories.system_config_repo import SystemConfigRepository
    from app.api.v1.routers.setup import is_setup_completed
    from app.config.logging_config import update_logging_level

    try:
        async with AsyncSessionLocal() as session:
            # Check if setup is completed
            setup_done = await is_setup_completed(session)
            SystemConfigCache.set_setup_completed(setup_done)
            
            repo = SystemConfigRepository(session)

            # --- Initialize Log Level ---
            log_level_config = await repo.get_by_key("system.log_level")
            if log_level_config and log_level_config.value:
                 # Extract level from dict or fallback to string (backward compatibility)
                 val = log_level_config.value
                 if isinstance(val, dict) and "level" in val:
                     level_str = str(val["level"]).upper()
                 else:
                     level_str = str(val).upper()
                 
                 update_logging_level(level_str)
                 logger.info(f"Initialized log level from DB: {level_str}")
            else:
                # Default behavior
                if not setup_done:
                    # Setup phase: Force DEBUG
                    update_logging_level("DEBUG")
                    logger.info("Setup not completed. Enforcing DEBUG log level.")
                else:
                    # Generic default
                    update_logging_level("INFO")
                    logger.info("No log level config found. Defaulting to INFO.")

            if setup_done:
                # Load allowed origins from DB
                config = await repo.get_by_key("security.allowed_origins")
                cors_enabled_config = await repo.get_by_key("security.cors_enabled")
                
                # Load CORS Enabled status
                cors_enabled = False
                if cors_enabled_config and cors_enabled_config.value is not None:
                     val = cors_enabled_config.value
                     if isinstance(val, dict) and "enabled" in val:
                         cors_enabled = bool(val["enabled"])
                     else:
                         cors_enabled = bool(val)
                
                SystemConfigCache.set_cors_enabled(cors_enabled)
                logger.info(f"CORS Enabled: {cors_enabled}")

                if config and isinstance(config.value, dict) and "origins" in config.value:
                    SystemConfigCache.set_allowed_origins(config.value["origins"])
                    logger.info(f"Loaded allowed origins from DB: {config.value['origins']}")
                else:
                     # Fallback to env var if DB config missing but setup is done
                     allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
                     origins = [o.strip() for o in allowed_origins_str.split(",") if o.strip()]
                     SystemConfigCache.set_allowed_origins(origins)
                     logger.info(f"Loaded allowed origins from ENV: {origins}")
            else:
                logger.info("Setup not completed. Allowing all origins for setup mode.")
                SystemConfigCache.set_cors_enabled(True) # Enable CORS for setup
    except Exception as e:
        logger.error(f"Failed to initialize system config cache: {e}")


    yield
    # This code runs on shutdown
    logger.info("Application shutdown.")


app = FastAPI(
    title="Secure Coding Platform API",
    version="0.1.0",
    description="API for the Secure Coding Platform, providing analysis, generation, and GRC features.",
    lifespan=lifespan,
)


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

    logger.info(
        f"Request to {request.url.path} completed with status {response.status_code}"
    )
    return response


# --- Dynamic CORS Middleware Configuration ---
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from app.core.config_cache import SystemConfigCache
from fastapi.responses import PlainTextResponse

class DynamicCORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Determine allowed origins based on state
        if not SystemConfigCache.is_setup_completed():
            allow_all = True
            allowed_origins = ["*"]
        else:
            allow_all = False
            # Check if CORS is explicitly permitted
            if not SystemConfigCache.is_cors_enabled():
                 allowed_origins = [] # Block external CORS
            else:
                 allowed_origins = SystemConfigCache.get_allowed_origins()
            
        origin = request.headers.get("origin")
        
        # Pass request to application
        response = await call_next(request)
        
        # Add CORS headers to response
        if origin:
            if allow_all or origin in allowed_origins:
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Credentials"] = "true"
                response.headers["Access-Control-Allow-Methods"] = "*"
                response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Correlation-ID, Accept, Origin, X-Requested-With"
        
        return response

@app.options("/{rest_of_path:path}")
async def preflight_handler(request: Request, rest_of_path: str):
    origin = request.headers.get("origin")
    if not SystemConfigCache.is_setup_completed():
         allowed = True
    else:
         # Check if CORS is enabled
         if not SystemConfigCache.is_cors_enabled():
              allowed = False
         else:
              allowed = origin and origin in SystemConfigCache.get_allowed_origins()

    if allowed and origin:
        response = PlainTextResponse("OK")
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Correlation-ID, Accept, Origin, X-Requested-With"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response
    
    # If not allowed, we don't return CORS headers, browser will block.
    return PlainTextResponse("Forbidden", status_code=403)

app.add_middleware(DynamicCORSMiddleware)
logger.info("Dynamic CORS Middleware configured.")


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
app.include_router(projects_router, prefix="/api/v1", tags=["Submissions"])

# Router for managing LLM Configurations
app.include_router(
    llm_router, prefix="/api/v1/admin", tags=["Admin: LLM Configurations"]
)

# Router for managing Frameworks
app.include_router(framework_router, prefix="/api/v1/admin", tags=["Admin: Frameworks"])

# Router for managing Agents
app.include_router(agent_router, prefix="/api/v1/admin", tags=["Admin: Agents"])

# Router for managing Prompt Templates
app.include_router(
    prompt_router, prefix="/api/v1/admin", tags=["Admin: Prompt Templates"]
)

# Router for managing RAG
app.include_router(rag_router, prefix="/api/v1/admin", tags=["Admin: RAG Management"])

# Router for System Logs
app.include_router(logs_router, prefix="/api/v1/admin", tags=["Admin: System Logs"])

# Router for Chat
app.include_router(chat_router, prefix="/api/v1/chat", tags=["Chat"])


# --- Include FastAPI Users Authentication Routers ---
app.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

# Custom refresh endpoint (fastapi-users does not provide one with BearerTransport)

app.include_router(
    refresh_router,
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

# Router for Initial Setup
app.include_router(
    setup_router,
    prefix="/api/v1/setup",
    tags=["Setup"],
)

# Router for System Configuration
app.include_router(
    admin_config_router,
    prefix="/api/v1",  # Prefix is defined in the router itself as /admin/system-config
)

# Router for LLM Configuration (Full CRUD)
app.include_router(
    admin_llm_config_router,
    prefix="/api/v1",  # Prefix is defined in the router itself as /admin/llm-config
)


# --- Root Endpoint ---
@app.get("/", tags=["Root"])
async def read_root():
    """A simple root endpoint to confirm the API is running."""
    return {"message": "Welcome to the Secure Coding Platform API!"}
