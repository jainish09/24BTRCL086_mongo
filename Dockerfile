# ThreatPulse SOC Platform & Threat Advisor - Complete Enterprise Dockerfile
# Packages Lab 7 through Lab 18 + Threat Advisor LLM & Sentinel Scanner
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    HOST=0.0.0.0

WORKDIR /app

# Install Python dependencies first for caching
COPY MongoDB_Combined_Docker_Pipeline/lab7/backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# 1. Copy the entire MongoDB Combined Pipeline (Labs 7-13, chapters, scripts & scanner)
COPY MongoDB_Combined_Docker_Pipeline/ /app/

# 2. Provide top-level backend & frontend mappings for path compatibility
COPY MongoDB_Combined_Docker_Pipeline/lab7/backend/ /app/backend/
COPY MongoDB_Combined_Docker_Pipeline/lab7/frontend/ /app/frontend/
COPY MongoDB_Combined_Docker_Pipeline/scanner/ /app/scanner/

# 3. Copy root chapters 14 through 18
COPY chapter-14/ /app/chapter-14/
COPY chapter-15/ /app/chapter-15/
COPY chapter-16/ /app/chapter-16/
COPY chapter-17/ /app/chapter-17/
COPY chapter-18/ /app/chapter-18/

WORKDIR /app/backend

EXPOSE 8080

# Health check verifying API and all routes readiness
HEALTHCHECK --interval=20s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=3)" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
