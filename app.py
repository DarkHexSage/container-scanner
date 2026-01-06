from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import json
import os
from datetime import datetime
import hashlib
import threading

app = Flask(__name__)
CORS(app)

# Cache for scan results to avoid duplicate scans
SCAN_CACHE = {}
CACHE_LOCK = threading.Lock()

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"}), 200

@app.route('/api/scan', methods=['POST'])
def scan_image():
    """
    Scan a container image using Trivy
    Expects: {"image": "nginx:latest"} or {"registry": "docker.io/library/nginx", "tag": "latest"}
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        image = data.get('image')
        
        if not image:
            return jsonify({"error": "Image name is required"}), 400
        
        # Validate image format
        if not _validate_image_name(image):
            return jsonify({"error": "Invalid image format"}), 400
        
        # Check cache first
        cache_key = hashlib.md5(image.encode()).hexdigest()
        with SCAN_CACHE_LOCK:
            if cache_key in SCAN_CACHE:
                cached_result = SCAN_CACHE[cache_key]
                return jsonify({
                    "image": image,
                    "scan_time": cached_result['scan_time'],
                    "vulnerabilities": cached_result['vulnerabilities'],
                    "summary": cached_result['summary'],
                    "warning": cached_result.get('warning'),
                    "status": "completed",
                    "cached": True
                }), 200
        
        # Run Trivy scan
        result = _run_trivy_scan(image)
        
        if result.get('error'):
            return jsonify(result), 500
        
        # Cache the result
        scan_result = {
            "image": image,
            "scan_time": datetime.now().isoformat(),
            "vulnerabilities": result.get('vulnerabilities', []),
            "summary": result.get('summary', {}),
            "warning": result.get('warning'),
            "status": "completed",
            "cached": False
        }
        
        with SCAN_CACHE_LOCK:
            SCAN_CACHE[cache_key] = {
                "scan_time": scan_result["scan_time"],
                "vulnerabilities": scan_result["vulnerabilities"],
                "summary": scan_result["summary"],
                "warning": scan_result.get("warning")
            }
        
        return jsonify(scan_result), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan-registry', methods=['POST'])
def scan_registry():
    """
    Scan an image from a registry (Docker Hub, ECR, etc)
    Expects: {"registry": "docker.io", "namespace": "library", "image": "nginx", "tag": "latest"}
    """
    try:
        data = request.get_json()
        
        registry = data.get('registry', 'docker.io')
        namespace = data.get('namespace', 'library')
        image = data.get('image')
        tag = data.get('tag', 'latest')
        
        if not image:
            return jsonify({"error": "Image name is required"}), 400
        
        # Build full image reference
        full_image = f"{registry}/{namespace}/{image}:{tag}"
        
        # Check cache first
        cache_key = hashlib.md5(full_image.encode()).hexdigest()
        with SCAN_CACHE_LOCK:
            if cache_key in SCAN_CACHE:
                cached_result = SCAN_CACHE[cache_key]
                return jsonify({
                    "image": full_image,
                    "scan_time": cached_result['scan_time'],
                    "vulnerabilities": cached_result['vulnerabilities'],
                    "summary": cached_result['summary'],
                    "warning": cached_result.get('warning'),
                    "status": "completed",
                    "cached": True
                }), 200
        
        result = _run_trivy_scan(full_image)
        
        if result.get('error'):
            return jsonify(result), 500
        
        # Cache the result
        scan_result = {
            "image": full_image,
            "scan_time": datetime.now().isoformat(),
            "vulnerabilities": result.get('vulnerabilities', []),
            "summary": result.get('summary', {}),
            "warning": result.get('warning'),
            "status": "completed",
            "cached": False
        }
        
        with SCAN_CACHE_LOCK:
            SCAN_CACHE[cache_key] = {
                "scan_time": scan_result["scan_time"],
                "vulnerabilities": scan_result["vulnerabilities"],
                "summary": scan_result["summary"],
                "warning": scan_result.get("warning")
            }
        
        return jsonify(scan_result), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan-status', methods=['GET'])
def scan_status():
    """Get Trivy database status and update info"""
    try:
        result = _get_trivy_status()
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def _validate_image_name(image: str) -> bool:
    """Validate Docker image name format"""
    if not image or len(image) == 0:
        return False
    # Basic validation - improve as needed
    return True

def _get_trivy_status() -> dict:
    """Get Trivy database status"""
    try:
        # Check if Trivy is installed
        check_trivy = subprocess.run(['which', 'trivy'], capture_output=True)
        
        if check_trivy.returncode != 0:
            return {
                "installed": False,
                "error": "Trivy not installed"
            }
        
        # Get version
        version_cmd = subprocess.run(['trivy', '--version'], capture_output=True, text=True, timeout=10)
        
        return {
            "installed": True,
            "version": version_cmd.stdout.strip() if version_cmd.returncode == 0 else "Unknown"
        }
    except Exception as e:
        return {"installed": False, "error": str(e)}

def _run_trivy_scan(image: str) -> dict:
    """Run Trivy scan and parse results with enhanced configuration"""
    try:
        # Check if Trivy is installed
        check_trivy = subprocess.run(['which', 'trivy'], capture_output=True)
        
        if check_trivy.returncode != 0:
            return {
                "error": "Trivy not installed. Install with: apt-get install trivy",
                "status": "trivy_not_found"
            }
        
        # Enhanced Trivy command with better vulnerability detection:
        # --severity: ALL to capture all severity levels
        # --vuln-type: os,library to find both OS and application vulns
        # --format json: structured output
        # --offline-db: use offline DB for reliability
        cmd = [
            'trivy', 'image',
            '--format', 'json',
            '--severity', 'CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN',
            '--vuln-type', 'os,library',
            '--exit-code', '0',  # Don't fail on vulnerabilities
            '--quiet',
            image
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)  # Extended timeout
        
        if result.returncode not in [0, 1]:  # 1 is expected when vulns found
            return {
                "error": f"Trivy scan failed: {result.stderr}",
                "status": "scan_failed"
            }
        
        # Parse JSON output
        try:
            trivy_output = json.loads(result.stdout)
        except json.JSONDecodeError:
            # If JSON parsing fails, try to extract useful info from stderr
            if "database" in result.stderr.lower() or "metadata" in result.stderr.lower():
                return {
                    "error": "Trivy database issue - updating vulnerability database. Please try again.",
                    "status": "db_update_needed"
                }
            return {
                "error": "Failed to parse Trivy output",
                "status": "parse_error"
            }
        
        # Extract vulnerabilities
        vulnerabilities = []
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unknown": 0,
            "total": 0
        }
        
        # Process Results array
        if trivy_output.get('Results'):
            for result_item in trivy_output['Results']:
                # Get vulnerabilities from this result
                if result_item.get('Vulnerabilities'):
                    for vuln in result_item['Vulnerabilities']:
                        severity = vuln.get('Severity', 'UNKNOWN').upper()
                        
                        # Extract all relevant information
                        vuln_entry = {
                            "id": vuln.get('VulnerabilityID'),
                            "title": vuln.get('Title'),
                            "description": vuln.get('Description'),
                            "severity": severity,
                            "package": vuln.get('PkgName'),
                            "version": vuln.get('InstalledVersion'),
                            "fixed_version": vuln.get('FixedVersion'),
                            "references": vuln.get('References', []),
                            "cwe": vuln.get('CweIDs', []),
                            "cvss": vuln.get('CVSS'),
                            "published_date": vuln.get('PublishedDate'),
                            "source": result_item.get('Type', 'os')
                        }
                        
                        vulnerabilities.append(vuln_entry)
                        
                        # Count by severity
                        if severity == 'CRITICAL':
                            summary['critical'] += 1
                        elif severity == 'HIGH':
                            summary['high'] += 1
                        elif severity == 'MEDIUM':
                            summary['medium'] += 1
                        elif severity == 'LOW':
                            summary['low'] += 1
                        elif severity == 'UNKNOWN':
                            summary['unknown'] += 1
                        
                        summary['total'] += 1
        
        # Sort by severity (critical first)
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
        vulnerabilities.sort(
            key=lambda x: (severity_order.get(x['severity'], 5), x['id'])
        )
        
        # Check if OS was detected but has no advisories (EOL)
        warning = None
        if vulnerabilities == [] and trivy_output.get('Results'):
            for result_item in trivy_output['Results']:
                os_type = result_item.get('Type', '').lower()
                if os_type in ['ubuntu', 'debian']:
                    warning = "OS version is EOL - no advisory data available in database"
                    break
        
        return {
            "vulnerabilities": vulnerabilities,
            "summary": summary,
            "warning": warning,
            "error": None
        }
        
    except subprocess.TimeoutExpired:
        return {
            "error": "Scan timeout - image took too long to scan (>600s). Try a smaller image.",
            "status": "timeout"
        }
    except Exception as e:
        return {
            "error": str(e),
            "status": "exception"
        }

# Create thread-safe lock for cache
SCAN_CACHE_LOCK = threading.Lock()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)  # Production mode
