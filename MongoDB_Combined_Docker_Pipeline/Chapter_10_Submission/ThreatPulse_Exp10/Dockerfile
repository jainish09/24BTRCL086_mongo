FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

WORKDIR /app/backend

ENV MONGODB_URI="mongodb://mongo1:27017,mongo2:27017,mongo3:27017/?replicaSet=rs0"
ENV PORT=8095
ENV HOST="0.0.0.0"

EXPOSE 8095

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8095"]
