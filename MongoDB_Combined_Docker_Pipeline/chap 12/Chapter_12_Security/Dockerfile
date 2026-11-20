# ==============================================================================
# Dockerfile: Chapter 12 Security Test Runner
# Standardized, slim Python environment for running TLS, RBAC, and Redaction tests
# ==============================================================================
FROM python:3.11-slim

# Prevent writing .pyc files and buffer output
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies (pymongo with TLS support, python-dotenv, cryptography)
RUN pip install --no-cache-dir \
    pymongo[tls]==4.18.2 \
    python-dotenv==1.2.1 \
    cryptography==46.0.5

# Copy project scripts
COPY *.py /app/
COPY .env.example /app/.env

# Create certs mount directory
RUN mkdir -p /app/certs

CMD ["python", "run_all_tests.py"]
