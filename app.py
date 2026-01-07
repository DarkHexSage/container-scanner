from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import json
import os
from datetime import datetime
import hashlib
import threading
import sqlite3

app = Flask(__name__)
CORS(app)

# Cache for scan results
SCAN_CACHE = {}
SCAN_CACHE_LOCK = threading.Lock()
CACHE_EXPIRY = 3600  # 1 hour in seconds
DB_PATH = '/tmp/scanner_cache.db'

# Initialize database
def init_db():
    """Initialize SQLite database for persistent cache"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        image_hash TEXT PRIMARY KEY,
        image_name TEXT,
        scan_time TEXT,
        vulnerabilities TEXT,
        summary TEXT,
        warning TEXT,
        cache_age_hours REAL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        image_name TEXT,
        scan_time TEXT,
        total_vulns INTEGER,
        critical INTEGER,
        high INTEGER,
        medium INTEGER,
        low INTEGER
    )''')
    conn.commit()
    conn.close()

init_db()

def _is_cache_expired(scan_time):
    """Check if cached result is older than CACHE_EXPIRY"""
    cached_timestamp = datetime.fromisoformat(scan_time)
    return (datetime.now() - cached_timestamp).total_seconds() > CACHE_EXPIRY

def _get_cache_age_hours(scan_time):
    """Get cache age in hours"""
    cached_timestamp = datetime.fromisoformat(scan_time)
    return round((datetime.now() - cached_timestamp).total_seconds() / 3600, 1)

def _save_to_db(image_hash, image_name, scan_result):
    """Save scan result to persistent database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO scans 
                     (image_hash, image_name, scan_time, vulnerabilities, summary, warning, cache_age_hours)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (image_hash, image_name, scan_result['scan_time'],
                   json.dumps(scan_result['vulnerabilities']),
                   json.dumps(scan_result['summary']),
                   scan_result.get('warning'),
                   0))
        
        # Save to history
        summary = scan_result['summary']
        c.execute('''INSERT INTO scan_history 
                     (image_name, scan_time, total_vulns, critical, high, medium, low)
                     VALUES (?, ?, ?, ?, ?, ?, ?)''',
                  (image_name, scan_result['scan_time'], summary['total'],
                   summary['critical'], summary['high'], summary['medium'], summary['low']))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"DB save error: {e}")

def _load_from_db(image_hash):
    """Load cached scan from persistent database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT scan_time, vulnerabilities, summary, warning FROM scans WHERE image_hash = ?', (image_hash,))
        row = c.fetchone()
        conn.close()
        
        if row:
            scan_time, vulns_json, summary_json, warning = row
            if not _is_cache_expired(scan_time):
                return {
                    'scan_time': scan_time,
                    'vulnerabilities': json.loads(vulns_json),
                    'summary': json.loads(summary_json),
                    'warning': warning,
                    'cache_age_hours': _get_cache_age_hours(scan_time)
                }
        return None
    except Exception as e:
        print(f"DB load error: {e}")
        return None

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"}), 200

@app.route('/api/scan', methods=['POST'])
def scan_image():
    """Scan a container image using Trivy"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        image = data.get('image')
        
        if not image:
            return jsonify({"error": "Image name is required"}), 400
        
        if not _validate_image_name(image):
            return jsonify({"error": "Invalid image format"}), 400
        
        cache_key = hashlib.md5(image.encode()).hexdigest()
        
        # Check in-memory cache first
        with SCAN_CACHE_LOCK:
            if cache_key in SCAN_CACHE:
                cached_result = SCAN_CACHE[cache_key]
                if not _is_cache_expired(cached_result['scan_time']):
                    return jsonify({
                        "image": image,
                        "scan_time": cached_result['scan_time'],
                        "vulnerabilities": cached_result['vulnerabilities'],
                        "summary": cached_result['summary'],
                        "warning": cached_result.get('warning'),
                        "status": "completed",
                        "cached": True,
                        "cache_source": "memory",
                        "cache_age_hours": _get_cache_age_hours(cached_result['scan_time'])
                    }), 200
                else:
                    del SCAN_CACHE[cache_key]
        
        # Check persistent database cache
        db_result = _load_from_db(cache_key)
        if db_result:
            return jsonify({
                "image": image,
                "scan_time": db_result['scan_time'],
                "vulnerabilities": db_result['vulnerabilities'],
                "summary": db_result['summary'],
                "warning": db_result.get('warning'),
                "status": "completed",
                "cached": True,
                "cache_source": "database",
                "cache_age_hours": db_result['cache_age_hours']
            }), 200
        
        # Run Trivy scan
        result = _run_trivy_scan(image)
        
        if result.get('error'):
            return jsonify(result), 500
        
        # Build response
        scan_result = {
            "image": image,
            "scan_time": datetime.now().isoformat(),
            "vulnerabilities": result.get('vulnerabilities', []),
            "summary": result.get('summary', {}),
            "warning": result.get('warning'),
            "status": "completed",
            "cached": False,
            "cache_source": None,
            "cache_age_hours": None
        }
        
        # Save to caches
        with SCAN_CACHE_LOCK:
            SCAN_CACHE[cache_key] = {
                "scan_time": scan_result["scan_time"],
                "vulnerabilities": scan_result["vulnerabilities"],
                "summary": scan_result["summary"],
                "warning": scan_result.get("warning")
            }
        
        _save_to_db(cache_key, image, scan_result)
        
        return jsonify(scan_result), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan-registry', methods=['POST'])
def scan_registry():
    """Scan an image from a registry"""
    try:
        data = request.get_json()
        
        registry = data.get('registry', 'docker.io')
        namespace = data.get('namespace', 'library')
        image = data.get('image')
        tag = data.get('tag', 'latest')
        
        if not image:
            return jsonify({"error": "Image name is required"}), 400
        
        full_image = f"{registry}/{namespace}/{image}:{tag}"
        cache_key = hashlib.md5(full_image.encode()).hexdigest()
        
        # Check in-memory cache
        with SCAN_CACHE_LOCK:
            if cache_key in SCAN_CACHE:
                cached_result = SCAN_CACHE[cache_key]
                if not _is_cache_expired(cached_result['scan_time']):
                    return jsonify({
                        "image": full_image,
                        "scan_time": cached_result['scan_time'],
                        "vulnerabilities": cached_result['vulnerabilities'],
                        "summary": cached_result['summary'],
                        "warning": cached_result.get('warning'),
                        "status": "completed",
                        "cached": True,
                        "cache_source": "memory",
                        "cache_age_hours": _get_cache_age_hours(cached_result['scan_time'])
                    }), 200
                else:
                    del SCAN_CACHE[cache_key]
        
        # Check database cache
        db_result = _load_from_db(cache_key)
        if db_result:
            return jsonify({
                "image": full_image,
                "scan_time": db_result['scan_time'],
                "vulnerabilities": db_result['vulnerabilities'],
                "summary": db_result['summary'],
                "warning": db_result.get('warning'),
                "status": "completed",
                "cached": True,
                "cache_source": "database",
                "cache_age_hours": db_result['cache_age_hours']
            }), 200
        
        result = _run_trivy_scan(full_image)
        
        if result.get('error'):
            return jsonify(result), 500
        
        scan_result = {
            "image": full_image,
            "scan_time": datetime.now().isoformat(),
            "vulnerabilities": result.get('vulnerabilities', []),
            "summary": result.get('summary', {}),
            "warning": result.get('warning'),
            "status": "completed",
            "cached": False,
            "cache_source": None,
            "cache_age_hours": None
        }
        
        with SCAN_CACHE_LOCK:
            SCAN_CACHE[cache_key] = {
                "scan_time": scan_result["scan_time"],
                "vulnerabilities": scan_result["vulnerabilities"],
                "summary": scan_result["summary"],
                "warning": scan_result.get("warning")
            }
        
        _save_to_db(cache_key, full_image, scan_result)
        
        return jsonify(scan_result), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/cache-stats', methods=['GET'])
def cache_stats():
    """Get cache statistics"""
    try:
        with SCAN_CACHE_LOCK:
            memory_cache_size = len(SCAN_CACHE)
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM scans')
        db_cache_size = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM scan_history')
        total_scans = c.fetchone()[0]
        
        c.execute('SELECT AVG(total_vulns) FROM scan_history')
        avg_vulns = c.fetchone()[0] or 0
        
        c.execute('SELECT image_name, scan_time FROM scan_history ORDER BY scan_time DESC LIMIT 5')
        recent = c.fetchall()
        
        conn.close()
        
        return jsonify({
            "memory_cache_entries": memory_cache_size,
            "database_cache_entries": db_cache_size,
            "total_scans_history": total_scans,
            "average_vulns_per_scan": round(avg_vulns, 1),
            "recent_scans": [{"image": r[0], "time": r[1]} for r in recent],
            "cache_expiry_seconds": CACHE_EXPIRY
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan-history', methods=['GET'])
def scan_history():
    """Get scan history and trends"""
    try:
        limit = request.args.get('limit', 50, type=int)
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''SELECT image_name, scan_time, total_vulns, critical, high, medium, low 
                     FROM scan_history 
                     ORDER BY scan_time DESC 
                     LIMIT ?''', (limit,))
        rows = c.fetchall()
        conn.close()
        
        history = [{
            "image": r[0],
            "scan_time": r[1],
            "total_vulns": r[2],
            "critical": r[3],
            "high": r[4],
            "medium": r[5],
            "low": r[6]
        } for r in rows]
        
        return jsonify({"history": history, "total": len(history)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan-status', methods=['GET'])
def scan_status():
    """Get Trivy database status"""
    try:
        result = _get_trivy_status()
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def _validate_image_name(image: str) -> bool:
    """Validate Docker image name format"""
    if not image or len(image) == 0:
        return False
    return True

def _get_trivy_status() -> dict:
    """Get Trivy database status"""
    try:
        check_trivy = subprocess.run(['which', 'trivy'], capture_output=True)
        
        if check_trivy.returncode != 0:
            return {"installed": False, "error": "Trivy not installed"}
        
        version_cmd = subprocess.run(['trivy', '--version'], capture_output=True, text=True, timeout=10)
        
        return {
            "installed": True,
            "version": version_cmd.stdout.strip() if version_cmd.returncode == 0 else "Unknown"
        }
    except Exception as e:
        return {"installed": False, "error": str(e)}

def _run_trivy_scan(image: str) -> dict:
    """Run Trivy scan with comprehensive detection"""
    try:
        check_trivy = subprocess.run(['which', 'trivy'], capture_output=True)
        
        if check_trivy.returncode != 0:
            return {"error": "Trivy not installed", "status": "trivy_not_found"}
        
        cmd = [
            'trivy', 'image',
            '--format', 'json',
            '--severity', 'CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN',
            '--vuln-type', 'os,library',
            '--detection-priority', 'comprehensive',
            '--exit-code', '0',
            '--quiet',
            image
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode not in [0, 1]:
            return {"error": f"Trivy scan failed: {result.stderr}", "status": "scan_failed"}
        
        try:
            trivy_output = json.loads(result.stdout)
        except json.JSONDecodeError:
            if "database" in result.stderr.lower() or "metadata" in result.stderr.lower():
                return {"error": "Trivy database issue - updating. Please try again.", "status": "db_update_needed"}
            return {"error": "Failed to parse Trivy output", "status": "parse_error"}
        
        vulnerabilities = []
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "total": 0}
        
        if trivy_output.get('Results'):
            for result_item in trivy_output['Results']:
                if result_item.get('Vulnerabilities'):
                    for vuln in result_item['Vulnerabilities']:
                        severity = vuln.get('Severity', 'UNKNOWN').upper()
                        
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
        
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
        vulnerabilities.sort(key=lambda x: (severity_order.get(x['severity'], 5), x['id']))
        
        warning = None
        if vulnerabilities == [] and trivy_output.get('Results'):
            for result_item in trivy_output['Results']:
                os_type = result_item.get('Type', '').lower()
                if os_type in ['ubuntu', 'debian']:
                    warning = "OS version is EOL - no advisory data available in database"
                    break
        
        return {"vulnerabilities": vulnerabilities, "summary": summary, "warning": warning, "error": None}
        
    except subprocess.TimeoutExpired:
        return {"error": "Scan timeout (>600s). Try a smaller image.", "status": "timeout"}
    except Exception as e:
        return {"error": str(e), "status": "exception"}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
