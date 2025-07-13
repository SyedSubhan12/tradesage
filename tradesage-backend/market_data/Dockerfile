# Use an official Python runtime as a parent image
FROM python:3.10-slim-buster

# Set the working directory in the container
WORKDIR /app

# Install system dependencies required for psycopg2 and other packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    musl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY ./requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Expose the port the app runs on
EXPOSE 8005

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8005"]