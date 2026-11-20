FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies & curl for container healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY MongoDB_Combined_Docker_Pipeline/lab7/backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend source & frontend UI
COPY MongoDB_Combined_Docker_Pipeline/lab7/backend/ /app/backend/
COPY MongoDB_Combined_Docker_Pipeline/lab7/frontend/ /app/frontend/

WORKDIR /app/backend

ENV HOST=0.0.0.0 PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8080/api/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]

