# ==============================================================================
# TraceX Cyber-Forensic Threat Defense Platform
# Production Dockerfile — Pure AWS S3 Storage & Headless Playwright Detonation
# ==============================================================================

FROM python:3.11-slim-bookworm

# Prevent Python from writing .pyc files & enable unbuffered stdout
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    PYTHONPATH="/app:/app/api_export" \
    PORT=8000

# Install base system dependencies and Chromium requirements for isolated Playwright sandbox
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    ca-certificates \
    build-essential \
    fontconfig \
    fonts-liberation \
    fonts-dejavu-core \
    # Chromium dependencies for Playwright
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    && rm -rf /var/lib/apt/lists/*

# Set up application workspace
WORKDIR /app

# Copy and install Python dependencies
COPY requirements-docker.txt /app/requirements-docker.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements-docker.txt

# Install Playwright Chromium headless browser binaries
RUN python -m playwright install chromium

# Copy codebase, SIH26 login portal, and TraceX browser extension
COPY gateway/ /app/gateway/
COPY api_export/ /app/api_export/
COPY SIH26/ /app/SIH26/
COPY extension/ /app/extension/
COPY docker-entrypoint.sh /app/docker-entrypoint.sh

# Create runtime directories for S3 vault cache and ensure correct permissions
RUN mkdir -p /app/gateway/data/s3_vault && \
    chmod +x /app/docker-entrypoint.sh

# Security Hardening: Run as dedicated non-root user
RUN groupadd -r tracex && useradd -r -g tracex -d /app -s /sbin/nologin tracex && \
    chown -R tracex:tracex /app

USER tracex

# Expose HTTP Gateway port
EXPOSE 8000

# Healthcheck testing pure S3 recent scans endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/scans || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["sh", "-c", "exec python -m uvicorn gateway.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
