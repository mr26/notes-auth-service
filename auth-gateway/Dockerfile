# ----------------------------
# Build stage
# ----------------------------
FROM python:3.12-slim AS builder

WORKDIR /app

# Install system deps needed for building wheels
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency definitions
COPY requirements.txt .

# Install Python deps into a temporary location
RUN pip install --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ----------------------------
# Runtime stage
# ----------------------------
FROM python:3.12-slim

WORKDIR /app

# Create non-root user
RUN useradd --create-home appuser

# Copy installed dependencies from builder stage
COPY --from=builder /install /usr/local

# Copy application code
COPY . .

# Runtime environment defaults (override via Helm)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

EXPOSE 8000

# Drop privileges
USER appuser

# Run FastAPI
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
