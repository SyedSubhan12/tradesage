# Note: Table creation is now handled by Alembic migrations
# Run migrations with: alembic upgrade head

app = FastAPI(
    title="Auth Service",
    description="Authentication and Authorization Service",
    version="1.0.0",
    lifespan=lifespan
) 