import React, { useState } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [image, setImage] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:5000';

  const handleScan = async (e) => {
    e.preventDefault();
    
    if (!image.trim()) {
      setError('Please enter an image name');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await axios.post(`${API_BASE}/api/scan`, {
        image: image.trim()
      });

      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Scan failed. Make sure the image exists.');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'CRITICAL': return '#e53935';
      case 'HIGH': return '#fb8c00';
      case 'MEDIUM': return '#fdd835';
      case 'LOW': return '#43a047';
      default: return '#666';
    }
  };

  return (
    <div className="container">
      <div className="scanner">
        <h1>🔐 Container Security Scanner</h1>
        <p className="subtitle">Scan Docker images for vulnerabilities using Trivy</p>

        <form onSubmit={handleScan} className="scan-form">
          <input
            type="text"
            value={image}
            onChange={(e) => setImage(e.target.value)}
            placeholder="e.g., nginx:latest, alpine:3.18"
            className="input-field"
            disabled={loading}
          />
          <button type="submit" disabled={loading} className="scan-btn">
            {loading ? 'Scanning...' : 'Scan Image'}
          </button>
        </form>

        {error && (
          <div className="error-box">
            <span className="error-icon">⚠️</span>
            {error}
          </div>
        )}

        {result && (
          <div className="results">
            <div className="result-header">
              <h2>Scan Results</h2>
              <span className="image-name">{result.image}</span>
            </div>

            <div className="summary-cards">
              <div className="summary-card critical">
                <div className="number">{result.summary.critical}</div>
                <div className="label">CRITICAL</div>
              </div>
              <div className="summary-card high">
                <div className="number">{result.summary.high}</div>
                <div className="label">HIGH</div>
              </div>
              <div className="summary-card medium">
                <div className="number">{result.summary.medium}</div>
                <div className="label">MEDIUM</div>
              </div>
              <div className="summary-card low">
                <div className="number">{result.summary.low}</div>
                <div className="label">LOW</div>
              </div>
            </div>

            {result.vulnerabilities.length > 0 ? (
              <div className="vulnerabilities-list">
                <h3>Found {result.vulnerabilities.length} Vulnerabilities</h3>
                {result.vulnerabilities.map((vuln, idx) => (
                  <div key={idx} className="vulnerability-item" style={{borderLeftColor: getSeverityColor(vuln.severity)}}>
                    <div className="vuln-header">
                      <span className="severity-badge" style={{backgroundColor: getSeverityColor(vuln.severity)}}>
                        {vuln.severity}
                      </span>
                      <span className="vuln-id">{vuln.id}</span>
                    </div>
                    <h4>{vuln.title}</h4>
                    <p className="description">{vuln.description}</p>
                    <div className="vuln-details">
                      <div className="detail">
                        <strong>Package:</strong> {vuln.package} {vuln.version && `(${vuln.version})`}
                      </div>
                      {vuln.fixed_version && (
                        <div className="detail">
                          <strong>Fixed Version:</strong> {vuln.fixed_version}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="success-box">
                ✅ No vulnerabilities found!
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
