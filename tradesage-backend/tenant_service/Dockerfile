# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY tenant_service/requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code and the common module
COPY tenant_service/ ./tenant_service/
COPY common/ ./common/

# Set the Python path
ENV PYTHONPATH=/app

# Expose the port the app runs on
EXPOSE 8003

# Define the command to run the application
CMD ["uvicorn", "tenant_service.main:app", "--host", "0.0.0.0", "--port", "8003"]
CMD ["uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8003"]
