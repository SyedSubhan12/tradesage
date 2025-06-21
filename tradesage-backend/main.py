# from fastapi import FastAPI
# from contextlib import asynccontextmanager
# import structlog
# from datetime import datetime, timezone
# from starlette_prometheus import metrics, PrometheusMiddleware
# from common.redis_client import redis_manager
# from common.logging_config import setup_logging

# # Set up structured logging
# setup_logging()
# logger = structlog.get_logger(__name__)



# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     # Startup: Connect to Redis
#     await redis_manager.connect()
#     logger.info("Redis connection established")
#     yield
#     # Shutdown: Disconnect from Redis
#     await redis_manager.disconnect()
#     logger.info("Redis connection closed")

# app = FastAPI(lifespan=lifespan)

# app.add_middleware(PrometheusMiddleware)
# app.add_route("/metrics", metrics)

# @app.get("/")
# async def root():
#     return {"message": "Hello World"}


# @app.get("/health")
# async def health_check():
#     return {
#         "status": "ok",
#         "service": "root",
#         "timestamp": datetime.now(timezone.utc).isoformat()
#     }


