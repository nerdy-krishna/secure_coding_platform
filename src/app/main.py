# src/app/main.py
import logging
import os
import json  # <-- ADD THIS IMPORT
from fastapi import FastAPI, Depends, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.encoders import jsonable_encoder
from starlette.responses import JSONResponse
from fastapi import FastAPI, Depends
from contextlib import asynccontextmanager
from fastapi.middleware.cors import CORSMiddleware

from .db.database import init_db  # For DB initialization on startup
from .api import endpoints as api_v1_endpoints  # Your existing API v1 router

# --- Authentication Imports ---
from .auth.core import fastapi_users, current_active_user
from .auth.backend import auth_backend  # Our custom backend
from .auth.schemas import UserRead, UserCreate, UserUpdate
from .auth.models import User  # For type hinting if needed

logger = logging.getLogger(__name__)  # Use __name__ for module-specific logger

# Basic logging configuration (can be enhanced later, e.g., with structured logging)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Application startup: Initializing database...")
    try:
        await init_db()
        logger.info("Database initialization successful.")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}", exc_info=True)
        # In a production scenario, you might want to prevent startup or have more robust error handling.
    yield
    logger.info("Application shutdown.")


app = FastAPI(
    title="Secure Coding Platform API",
    version="0.1.0",
    description="API for the Secure Coding Platform, providing analysis, generation, and GRC features.",
    lifespan=lifespan,
    # You can add docs_url, redoc_url, openapi_url configurations here if needed
)

# --- CORS Middleware Configuration ---
# This is crucial for frontend interaction, especially with credentials (cookies).
# Origins should be an explicit list in production.
# For development, allowing localhost with specific ports is common.
# The .env file could define ALLOWED_ORIGINS as a comma-separated string.
allowed_origins_str = os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
)
origins = [
    origin.strip() for origin in allowed_origins_str.split(",") if origin.strip()
]

if not origins:  # Fallback if ALLOWED_ORIGINS is empty or misconfigured
    origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]  # Default Vite dev port
    logger.warning(
        f"ALLOWED_ORIGINS environment variable not set or empty. Defaulting to: {origins}"
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,  # IMPORTANT: This must be True for cookies to be sent/received
    allow_methods=["*"],  # Allows all standard methods
    allow_headers=["*"],  # Allows all headers
    # expose_headers=["Content-Disposition"], # Example if you need to expose specific headers
)
logger.info(f"CORS middleware configured for origins: {origins}")


# --- Temporary Debugging Exception Handler for 422 Errors ---
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Catches Pydantic validation errors and provides detailed logging for debugging.
    """
    # Print the detailed errors directly to the console for maximum visibility.
    print("\n====== PYDANTIC VALIDATION ERROR ======")
    print(f"URL: {request.method} {request.url}")
    # exc.errors() gives a list of dictionaries with all details
    try:
        # Try to pretty-print the JSON body of the original request
        request_body = await request.json()
        print(f"REQUEST BODY:\n{json.dumps(request_body, indent=2)}")
    except Exception:
        print("REQUEST BODY: Could not parse request body as JSON.")

    print(f"VALIDATION DETAIL:\n{json.dumps(exc.errors(), indent=2)}")
    print("======================================\n")

    # For development, it's helpful to return the detailed error to the frontend.
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=jsonable_encoder(
            {"detail": exc.errors()}
        ),  # Return the full error detail
    )


# --- End of Debugging Exception Handler ---

# --- Include API v1 Router (Your application-specific endpoints) ---
app.include_router(api_v1_endpoints.router, prefix="/api/v1", tags=["API Endpoints"])


# --- Include FastAPI Users Authentication Routers ---
# Login endpoint (e.g., /api/v1/auth/login)
# Uses the `auth_backend` which includes our CustomCookieJWTStrategy
app.include_router(
    fastapi_users.get_auth_router(
        auth_backend
    ),  # Uses the backend that handles JWT and refresh cookie
    prefix="/api/v1/auth",  # Changed from /jwt to just /auth to simplify paths
    tags=["Authentication"],
)

# Registration endpoint (e.g., /api/v1/auth/register)
app.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

# Users routes (e.g., /api/v1/users/me, /api/v1/users/{id})
app.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate),
    prefix="/api/v1/users",
    tags=["Users"],
)

# Optional: Forgot password and email verification routers
# These require email sending capabilities to be configured.
# We can enable them later when email sending is set up.
# app.include_router(
#     fastapi_users.get_forgot_password_router(),
#     prefix="/api/v1/auth",
#     tags=["Authentication"],
# )
# app.include_router(
#     fastapi_users.get_verify_router(UserRead),
#     prefix="/api/v1/auth",
#     tags=["Authentication"],
# )
# app.include_router(
#     fastapi_users.get_reset_password_router(), # Need this if using forgot_password
#     prefix="/api/v1/auth/reset-password", # Usually separate prefix from forgot
#     tags=["Authentication"],
# )


# --- Example Protected Endpoint ---
@app.get("/api/v1/protected-example", response_model=UserRead, tags=["Examples"])
async def get_protected_example(user: User = Depends(current_active_user)):
    """
    An example endpoint that requires an active authenticated user.
    Returns the current user's details.
    """
    return user


# --- Root Endpoint ---
@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Welcome to the Secure Coding Platform API!"}
