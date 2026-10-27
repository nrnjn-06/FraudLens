# Use official Python 3.11 slim image
FROM python:3.11-slim

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system C libraries required by PyZbar (libzbar0) and OpenCV (libgl1, libglib2.0-0)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    libgl1 \
    libglib2.0-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r ./backend/requirements.txt

# Copy backend source code and ML models
COPY backend ./backend

# Create runtime data directory for SQLite database and cache
RUN mkdir -p /app/data/processed/urls/.tld_cache

# Default port (Render/Railway inject $PORT at runtime)
ENV PORT=8000
EXPOSE 8000

# Start Uvicorn bound to 0.0.0.0 and dynamic $PORT
CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
