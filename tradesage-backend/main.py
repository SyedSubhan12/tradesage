from fastapi import FastAPI
from contextlib import asynccontextmanager
from common.redis_client import redis_manager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Connect to Redis
    await redis_manager.connect()
    print("Redis connection established")
    yield
    # Shutdown: Disconnect from Redis
    await redis_manager.disconnect()
    print("Redis connection closed")

app = FastAPI(lifespan=lifespan)

@app.get("/")
async def root():
    return {"message": "Hello World"}
