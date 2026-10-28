# Containerized Test & Execution Environment for AWS Guardrails Engine
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source and test codebase
COPY . .

# Run validation suite on container start
CMD ["python", "-m", "src.cli", "simulate"]
