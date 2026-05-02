# Multi-stage build for Health Agent
# Stage 1: Build
FROM python:3.10-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml uv.lock* ./
COPY agents/health_agent/ ./agents/health_agent/

# Install dependencies with uv
RUN pip install --no-cache-dir uv && \
    uv export --no-hashes --format requirements-txt > requirements.txt

# Stage 2: Runtime
FROM python:3.10-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements from builder
COPY --from=builder /build/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY agents/health_agent/ ./

# Create non-root user
RUN useradd -m -u 1000 healthagent && chown -R healthagent:healthagent /app
USER healthagent

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import sys; sys.exit(0)" || exit 1

# Set entrypoint
ENTRYPOINT ["python", "main.py"]
CMD []
