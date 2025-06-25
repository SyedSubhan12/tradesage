import httpx
import logging
from fastapi import FastAPI, Request, HTTPException, status, APIRouter, Response
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import Response
from fastapi.staticfiles import StaticFiles
import httpx
import asyncio
import structlog
from datetime import datetime, timezone
from starlette_prometheus import metrics, PrometheusMiddleware

from common.config import settings
from common.auth import auth_manager, TokenExpiredError
from common.logging_config import setup_logging

# Configure structured logging
setup_logging()
logger = structlog.get_logger(__name__)



# Parse public paths from settings to handle exact matches and wildcard prefixes
raw_paths = settings.API_GATEWAY_PUBLIC_PATHS.split(',')
exact_public_paths = {p for p in raw_paths if not p.endswith('*')}
prefix_public_paths = {p.rstrip('*') for p in raw_paths if p.endswith('*')}

app = FastAPI(title="TradeSage API Gateway")
api_router = APIRouter(prefix="/api")

# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS.split(','),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(PrometheusMiddleware)
# ---------- DEBUG ----------
print(">>> Dumping user_middleware BEFORE server starts")
for idx, m in enumerate(app.user_middleware, 1):
    print(f"[MW {idx}] type={type(m)}  content={m}")
print(">>> END DUMP")
# ---------------------------
app.add_route("/metrics", metrics)


# --- Helper function for public path check ---
def is_public_path(path: str) -> bool:
    """Checks if a given path is public based on the configured patterns."""
    if path in exact_public_paths:
        return True
    for prefix in prefix_public_paths:
        if path.startswith(prefix):
            return True
    return False

# --- Authentication Middleware ---
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    # Allow OPTIONS requests for CORS preflight
    if request.method == "OPTIONS":
        return await call_next(request)

    # Check if the requested path is for the API
    # Forward standalone OAuth routes (e.g., /oauth/google/callback) without /api prefix
    if request.url.path.startswith('/oauth/'):
        # Skip auth check to allow Google callback
        return await call_next(request)

    if not request.url.path.startswith('/api'):
        return await call_next(request)

    # Check if the requested API path is public
    if is_public_path(request.url.path):
        logger.info(f"Public API route accessed: {request.url.path}")
        return await call_next(request)

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        logger.warning(f"Unauthorized: Missing or invalid Authorization header for API path {request.url.path}")
        return Response(status_code=401, content="Unauthorized", headers={"WWW-Authenticate": "Bearer"})

    token = auth_header.split(" ")[1]

    try:
        payload = auth_manager.decode_token(token, is_refresh=False)
        if not payload:
            logger.warning(f"Forbidden: Invalid token payload for API path {request.url.path}")
            return Response(status_code=403, content="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
        
        request.state.user = payload
        logger.info(f"Authenticated user {payload.user_id} for API path {request.url.path}")

    except TokenExpiredError:
        logger.warning(f"Unauthorized: Expired token for API path {request.url.path}")
        return Response(status_code=401, content="Token has expired", headers={"WWW-Authenticate": "Bearer"})
    except Exception as e:
        logger.error(f"An unexpected error occurred during token validation for API path {request.url.path}: {e}", exc_info=True)
        return Response(status_code=403, content="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})

    return await call_next(request)

# --- API Reverse Proxy Logic ---
# Proxy for paths starting with /api/
@api_router.api_route("/{path:path}")
async def reverse_proxy(request: Request, path: str):
    async with httpx.AsyncClient() as client:
        # Reconstruct the downstream URL by prepending the service URL to the path
        # The path from the router will not include the '/api' prefix
        if path.startswith("auth/") or path.startswith("oauth/"):
            downstream_url = f"{settings.AUTH_SERVICE_URL}/{path}"
        elif path.startswith("users/"):
            # Assuming USER_SERVICE_URL is configured for user-related paths
            downstream_url = f"{settings.USER_SERVICE_URL}/{path}"
        elif path.startswith("tenant/"):
            # Assuming TENANT_SERVICE_URL is configured for tenant-related paths
            downstream_url = f"{settings.TENANT_SERVICE_URL}/{path}"
        elif path.startswith("sessions/"):
            downstream_url = f"{settings.SESSION_SERVICE_URL}/{path}"
        else:
            logger.warning(f"Unknown API path requested: {path}")
            return Response(status_code=404, content="Not Found")

        headers = dict(request.headers)
        headers.pop("host", None)

        try:
            logger.info(f"Proxying API request for /api/{path} to {downstream_url}")
            downstream_response = await client.request(
                method=request.method,
                url=downstream_url,
                headers=headers,
                params=request.query_params,
                content=request.stream(),
                timeout=30.0,
            )
        except httpx.ConnectError as e:
            logger.error(f"Connection to downstream service failed: {downstream_url}. Error: {e}")
            return Response(status_code=503, content="Service Unavailable")

        return StreamingResponse(
            downstream_response.aiter_raw(),
            status_code=downstream_response.status_code,
            headers=dict(downstream_response.headers),
        )

@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check(response: Response):
    """
    Health check for the API Gateway.
    Verifies its own status and checks downstream services.
    """
    downstream_services = {
        "auth_service": f"{settings.AUTH_SERVICE_URL}/health",
        "session_service": f"{settings.SESSION_SERVICE_URL}/health"
    }
    service_statuses = {}
    is_healthy = True

    async with httpx.AsyncClient() as client:
        for service, url in downstream_services.items():
            try:
                resp = await client.get(url, timeout=5.0)
                if resp.status_code == 200:
                    service_statuses[service] = "ok"
                else:
                    service_statuses[service] = "error"
                    is_healthy = False
            except httpx.RequestError as e:
                service_statuses[service] = "error"
                is_healthy = False
                logger.error("Health check for service failed", service=service, error=str(e))

    response_payload = {
        "status": "ok" if is_healthy else "error",
        "service": "api-gateway",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dependencies": service_statuses,
    }

    if not is_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return response_payload




# Include the API router in the main application
app.include_router(api_router)

# Proxy routes without /api prefix for OAuth callbacks
@app.api_route("/oauth/{path:path}")
async def oauth_proxy(request: Request, path: str):
    # Reuse the same reverse proxy function
    return await reverse_proxy(request, f"oauth/{path}")

# --- SPA Static File Serving ---
# This must be the last mount, as it includes a catch-all route.
# It serves the built frontend from the 'dist' directory.
from pathlib import Path

# Attempt to find and mount the built frontend
HERE = Path(__file__).resolve().parent
# Look for common build output directories (adjust as needed)
spa_dirs = [
    HERE / "/home/zs/Tradesage/frontend/dist",  # Common Vite/React/Vue
    # HERE / ".." / "dist",               # Common alternative
    # HERE / ".." / "build",              # Common Create React App
]

for spa_dir in spa_dirs:
    spa_dir = spa_dir.resolve()
    if spa_dir.exists() and spa_dir.is_dir():
        logger.info(f"Mounting SPA from: {spa_dir}")
        app.mount("/", StaticFiles(directory=str(spa_dir), html=True), name="static")
        break
else:
    logger.warning(
        "No SPA build directory found. Expected one of: "
        + ", ".join(str(d) for d in spa_dirs)
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.2", port=8001, reload=True)
