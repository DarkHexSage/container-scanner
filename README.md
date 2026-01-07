# 🔐 Container Security Scanner

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)](https://www.python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0.0-black?logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![React](https://img.shields.io/badge/React-18.2-61dafb?logo=react&logoColor=white)](https://react.dev)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ed?logo=docker&logoColor=white)](https://www.docker.com)
[![Trivy](https://img.shields.io/badge/Trivy-0.68+-1652f0?logo=aqua&logoColor=white)](https://github.com/aquasecurity/trivy)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)]()

A blazingly fast vulnerability scanner for Docker container images powered by Trivy with caching, beautiful UI, and production-grade performance.

---

## 📑 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Tech Stack](#-tech-stack)
- [Test Images](#-test-images)
- [Performance](#-performance)
- [API Reference](#-api-reference)
- [Configuration](#-configuration)
- [How It Works](#-how-it-works)
- [Security](#-security)
- [Recommendations](#-recommendations)

---

## ✨ Features

- **Real-time Scanning** - Detect CVEs, misconfigurations, and exposed secrets instantly
- **Severity Classification** - CRITICAL, HIGH, MEDIUM, LOW with CVSS scores
- **Smart Caching** - Sub-500ms scans for repeated images
- **Complete Metadata** - CVE IDs, CWE numbers, publication dates, and references
- **EOL Detection** - Warnings for end-of-life OS versions
- **Production Ready** - Single-CPU optimized with Gunicorn workers
- **Beautiful UI** - Dark-themed, responsive interface with animations
- **Thread-Safe** - Concurrent request handling with proper locking

---

## 🚀 Quick Start

### Docker Compose (Recommended)

```bash
# Clone/update repository
git clone <repo> && cd container-scanner

# Deploy
docker-compose down
docker-compose up --build -d

# Open UI
open http://localhost:3000

# Test scan
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"image": "ubuntu:22.04"}'
```

### Local Development

```bash
# Backend
pip install -r requirements.txt
python app.py  # Runs on http://localhost:5000

# Frontend (new terminal)
cd frontend
npm install
npm start  # Runs on http://localhost:3000
```

---

## 📊 Tech Stack

### Frontend
| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | React | 18.2.0 |
| HTTP Client | Axios | 1.6.0 |
| Styling | CSS3 | Custom Dark Theme |
| Build Tool | React Scripts | 5.0.1 |

### Backend
| Component | Technology | Version |
|-----------|-----------|---------|
| Framework | Flask | 3.0.0 |
| Server | Gunicorn | 21.2.0 |
| CORS | Flask-CORS | 4.0.0 |
| Caching | In-Memory (Thread-Safe) | - |

### Scanner & Infrastructure
| Component | Technology | Details |
|-----------|-----------|---------|
| Scanner | Trivy | 0.68+ |
| Detection | Comprehensive Mode | Upstream + Vendor |
| Container Runtime | Docker & Compose | 3.8+ |
| Database | Trivy Vulnerability DB | Auto-Updated Daily |
| Optimization | Single-CPU | 0.75 CPU backend, 0.25 CPU frontend |

---

## 🧪 Test Images

### ✅ Modern & Secure (0-30 vulns)

```
alpine:3.20              ✅  2-5 vulns       ⭐ BEST
debian:12                ✅  5-15 vulns      ⭐ BEST
ubuntu:22.04             ✅  5-15 vulns      👍 EXCELLENT
nginx:latest             ✅  2-10 vulns      👍 GOOD
python:3.12-alpine       ✅  8-20 vulns      👍 GOOD
node:22-alpine           ✅  3-10 vulns      👍 GOOD
golang:1.22-alpine       ✅  2-8 vulns       👍 GOOD
```

### ⚠️ Older But Maintained (20-100 vulns)

```
ubuntu:20.04             ⚠️   5-15 vulns      Still Supported
debian:11                ⚠️   10-30 vulns     Stable
rocky:9                  ⚠️   15-40 vulns     Good
centos:8                 ⚠️   20-50 vulns     Okay
```

### 🔴 EOL/Dangerous (Shows Warning)

```
ubuntu:18.04             🔴  20-40 vulns      ⚠️ EOL April 2023
centos:7                 🔴  50-100 vulns     ⚠️ EOL June 2024
debian:10                🔴  30-80 vulns      ⚠️ EOL Sept 2024
ubuntu:20.04 (old)       🔴  5-15 vulns       ⚠️ EOL April 2025
```

### 💀 Critical - Do NOT Use

```
ubuntu:16.04             ❌  No Data          EOL April 2021
python:3.6               ❌  ~9,000 vulns     Completely Broken
debian:8                 ❌  100-200 vulns    Severely Vulnerable
php:5.6                  ❌  300+ vulns       Pre-Historic
```

---

## ⚡ Performance

| Scenario | Time | Notes |
|----------|------|-------|
| **First Scan** | 30-90s | Downloads image + pre-warms database |
| **Cached Scan** | <500ms | In-memory result, instant response |
| **Database Update** | Auto | Trivy DB updates daily automatically |
| **Concurrent Requests** | 2 workers | Handles multiple scans simultaneously |

---

## 🔧 API Reference

### Scan Image

**Endpoint:** `POST /api/scan`

**Request:**
```json
{
  "image": "ubuntu:22.04"
}
```

**Response:**
```json
{
  "image": "ubuntu:22.04",
  "scan_time": "2025-01-06T22:50:00Z",
  "vulnerabilities": [
    {
      "id": "CVE-2025-4802",
      "severity": "MEDIUM",
      "package": "libc6",
      "version": "2.31-0ubuntu9.17",
      "fixed_version": "2.31-0ubuntu9.18",
      "cvss": {"redhat": {"V3Score": 7}},
      "cwe": ["CWE-426"],
      "published_date": "2025-05-16"
    }
  ],
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 3,
    "low": 5,
    "total": 9
  },
  "warning": null,
  "cached": false
}
```

### Health Check

**Endpoint:** `GET /api/health`

**Response:**
```json
{
  "status": "healthy"
}
```

---

## 📋 Configuration

### Adjust Scan Timeout

**File:** `app.py` (line with subprocess.run)

```python
timeout=600  # Change to 300, 900, 1200 (seconds)
```

### Adjust Worker Count

**File:** `Dockerfile` (CMD line)

```dockerfile
--workers 2  # Change to 1, 3, 4 (based on CPU cores)
```

### Adjust Resource Limits

**File:** `docker-compose.yml`

```yaml
deploy:
  resources:
    limits:
      cpus: '0.75'      # Adjust CPU allocation
      memory: 1536M     # Adjust memory allocation
```

## 📝 How It Works

```
1. User submits image in UI
   ↓
2. Frontend sends POST to /api/scan
   ↓
3. Backend checks in-memory cache
   ├─ Hit  → Return cached result (<500ms)
   └─ Miss → Continue to step 4
   ↓
4. Launch Trivy scan subprocess
   ├─ --detection-priority comprehensive
   ├─ --severity CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN
   └─ --vuln-type os,library
   ↓
5. Trivy compares packages against vulnerability DB
   ↓
6. Parse JSON results
   ├─ Extract CVE metadata
   ├─ Sort by severity
   └─ Detect EOL OS versions
   ↓
7. Cache result in memory (thread-safe)
   ↓
8. Return to frontend with all metadata
   ↓
9. UI displays beautifully formatted results
```

## 🔒 Security

- ✅ API validates image names before scanning
- ✅ CORS enabled only for localhost/frontend
- ✅ No sensitive data stored (cache in-memory only)
- ✅ Results cleared on container restart
- ✅ No network egress except to Docker Hub/registries
- ✅ Health checks prevent crashing containers

---

## 🎯 Recommendations

### Production Images ✅

```
✅ ubuntu:22.04         - LTS, 10 years support
✅ debian:12            - Latest stable
✅ alpine:3.20          - Minimal, well-maintained
✅ rocky:9              - RHEL-compatible
```

### Avoid ❌

```
❌ ubuntu:16.04/18.04   - EOL, no security updates
❌ debian:8/9           - Severely outdated
❌ python:3.6           - Completely broken (~9k vulns)
❌ php:5.6              - Pre-historic
```

---

---
## Demo

---

## 📄 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

- **Trivy** - Aqua Security's excellent vulnerability scanner
- **Flask** - Lightweight Python framework
- **React** - Modern frontend library
- **Docker** - Container platform

---
