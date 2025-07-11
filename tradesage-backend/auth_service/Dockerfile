FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
        gcc \ 
        libpq-dev \ 
        && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY auth_service/app/ ./app/
COPY ../common/ ./common/

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:8000/health || exit 1

# Run app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
