from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import json
import os
from datetime import datetime

app = Flask(__name__)
CORS(app)

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
        
        # Run Trivy scan
        result = _run_trivy_scan(image)
        
        if result.get('error'):
            return jsonify(result), 500
        
        return jsonify({
            "image": image,
            "scan_time": datetime.now().isoformat(),
            "vulnerabilities": result.get('vulnerabilities', []),
            "summary": result.get('summary', {}),
            "status": "completed"
        }), 200
        
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
        
        result = _run_trivy_scan(full_image)
        
        if result.get('error'):
            return jsonify(result), 500
        
        return jsonify({
            "image": full_image,
            "scan_time": datetime.now().isoformat(),
            "vulnerabilities": result.get('vulnerabilities', []),
            "summary": result.get('summary', {}),
            "status": "completed"
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def _validate_image_name(image: str) -> bool:
    """Validate Docker image name format"""
    if not image or len(image) == 0:
        return False
    # Basic validation - improve as needed
    return True

def _run_trivy_scan(image: str) -> dict:
    """Run Trivy scan and parse results"""
    try:
        # Check if Trivy is installed
        check_trivy = subprocess.run(['which', 'trivy'], capture_output=True)
        
        if check_trivy.returncode != 0:
            return {
                "error": "Trivy not installed. Install with: apt-get install trivy",
                "status": "trivy_not_found"
            }
        
        # Run Trivy scan with JSON output
        cmd = ['trivy', 'image', '--format', 'json', '--quiet', image]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode != 0:
            return {
                "error": f"Trivy scan failed: {result.stderr}",
                "status": "scan_failed"
            }
        
        # Parse JSON output
        try:
            trivy_output = json.loads(result.stdout)
        except json.JSONDecodeError:
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
            "total": 0
        }
        
        if trivy_output.get('Results'):
            for result_item in trivy_output['Results']:
                if result_item.get('Vulnerabilities'):
                    for vuln in result_item['Vulnerabilities']:
                        severity = vuln.get('Severity', 'UNKNOWN').upper()
                        
                        vulnerabilities.append({
                            "id": vuln.get('VulnerabilityID'),
                            "title": vuln.get('Title'),
                            "description": vuln.get('Description'),
                            "severity": severity,
                            "package": vuln.get('PkgName'),
                            "version": vuln.get('InstalledVersion'),
                            "fixed_version": vuln.get('FixedVersion'),
                            "references": vuln.get('References', [])
                        })
                        
                        # Count by severity
                        if severity == 'CRITICAL':
                            summary['critical'] += 1
                        elif severity == 'HIGH':
                            summary['high'] += 1
                        elif severity == 'MEDIUM':
                            summary['medium'] += 1
                        elif severity == 'LOW':
                            summary['low'] += 1
                        
                        summary['total'] += 1
        
        return {
            "vulnerabilities": vulnerabilities,
            "summary": summary,
            "error": None
        }
        
    except subprocess.TimeoutExpired:
        return {
            "error": "Scan timeout - image took too long to scan",
            "status": "timeout"
        }
    except Exception as e:
        return {
            "error": str(e),
            "status": "exception"
        }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
