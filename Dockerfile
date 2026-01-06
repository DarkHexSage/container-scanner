FROM python:3.11-slim

# Install dependencies for Trivy and security tools
RUN apt-get update && \
    apt-get install -y \
    curl \
    gnupg \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy using official method with version pinning
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin && \
    trivy --version && \
    trivy image --download-db-only

# Pre-warm the vulnerability database for better first-scan performance
RUN trivy image --severity CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN --format json --quiet alpine:latest > /dev/null 2>&1 || true

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 5000

# Run in production mode with gunicorn for better performance
RUN pip install --no-cache-dir gunicorn==21.2.0

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--worker-class", "sync", "--timeout", "600", "app:app"]
