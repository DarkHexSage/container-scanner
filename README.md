# 🔐 Container Security Scanner

A full-stack application to scan Docker images for vulnerabilities using Trivy.

**Stack:** Flask + React + Docker

## Features

- Scan container images by name (e.g., `nginx:latest`)
- Scan from any registry (Docker Hub, ECR, etc)
- Real-time vulnerability detection with Trivy
- Severity classification (CRITICAL, HIGH, MEDIUM, LOW)
- Beautiful React UI with detailed vulnerability info
- Docker containerization with docker-compose

## Quick Start

### Option 1: Run with Docker Compose (Recommended)

```bash
# Build and run both services
docker-compose up --build

# Open browser to http://localhost:3000
```

### Option 2: Run Locally

**Backend:**
```bash
pip install -r requirements.txt
python app.py
# Runs on http://localhost:5000
```

**Frontend:**
```bash
cd frontend
npm install
npm start
# Runs on http://localhost:3000
```

## API Endpoints

### Scan Image
```bash
POST /api/scan
Content-Type: application/json

{
  "image": "nginx:latest"
}
```

### Scan from Registry
```bash
POST /api/scan-registry
Content-Type: application/json

{
  "registry": "docker.io",
  "namespace": "library",
  "image": "nginx",
  "tag": "latest"
}
```

## Requirements

- Docker & Docker Compose
- Node.js 18+ (for local frontend development)
- Python 3.11+ (for local backend)
- Trivy installed (automatically in Docker image)

## Environment Variables

**Frontend (.env):**
```
REACT_APP_API_URL=http://localhost:5000
```

## Testing

Try these images:
- `nginx:latest`
- `ubuntu:22.04`
- `python:3.9`
- `alpine:latest`

## Architecture

```
container-scanner/
├── app.py                 # Flask backend
├── requirements.txt       # Python dependencies
├── Dockerfile            # Backend image
├── docker-compose.yml    # Orchestration
└── frontend/
    ├── src/
    │   ├── App.js       # Main React component
    │   ├── App.css      # Styling
    │   └── index.js
    ├── public/
    │   └── index.html
    ├── package.json     # Node dependencies
    └── Dockerfile       # Frontend image
```

## Performance Notes

- First scan might take time (image download)
- Subsequent scans of same image are faster
- Trivy caches vulnerability database

## Security

- API validates image names
- Timeout protection (300s per scan)
- CORS enabled for frontend communication
- No sensitive data stored


## Screenshots

---

**Built for:** Full-stack security engineering portfolio
