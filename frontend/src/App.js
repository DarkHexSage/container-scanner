import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

function App() {
  const [image, setImage] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [cached, setCached] = useState(false);
  const [cacheAge, setCacheAge] = useState(null);
  const [trivyStatus, setTrivyStatus] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [cacheStats, setCacheStats] = useState(null);
  const [showStats, setShowStats] = useState(false);
  const VULNS_PER_PAGE = 50;
  const API_BASE = process.env.REACT_APP_API_URL || '/api';

  // Check Trivy status on mount
  useEffect(() => {
    const checkTrivy = async () => {
      try {
        const response = await axios.get(`${API_BASE}/scan-status`);
        setTrivyStatus(response.data);
      } catch (err) {
        console.error('Failed to check Trivy status:', err);
      }
    };
    checkTrivy();
    
    // Load cache stats
    loadCacheStats();
  }, []);

  const loadCacheStats = async () => {
    try {
      const response = await axios.get(`${API_BASE}/cache-stats`);
      setCacheStats(response.data);
    } catch (err) {
      console.error('Failed to load cache stats:', err);
    }
  };

  const handleScan = async (e) => {
    e.preventDefault();
    
    if (!image.trim()) {
      setError('Please enter an image name');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);
    setCached(false);
    setCacheAge(null);
    setCurrentPage(1);

    try {
      const response = await axios.post(`${API_BASE}/api/scan`, {
        image: image.trim()
      });

      setResult(response.data);
      setCached(response.data.cached === true);
      if (response.data.cache_age_hours) {
        setCacheAge(response.data.cache_age_hours);
      }
      loadCacheStats();
    } catch (err) {
      const errorMsg = err.response?.data?.error || 'Scan failed. Make sure the image exists.';
      setError(errorMsg);
      
      if (err.response?.data?.status === 'db_update_needed') {
        setError(errorMsg + ' Trivy is updating its vulnerability database. Please wait a moment and try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'CRITICAL': return '#ef4444';
      case 'HIGH': return '#f97316';
      case 'MEDIUM': return '#eab308';
      case 'LOW': return '#22c55e';
      case 'UNKNOWN': return '#8b5cf6';
      default: return '#64748b';
    }
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  };

  // Pagination logic
  const startIdx = (currentPage - 1) * VULNS_PER_PAGE;
  const endIdx = startIdx + VULNS_PER_PAGE;
  const paginatedVulns = result?.vulnerabilities?.slice(startIdx, endIdx) || [];
  const totalPages = Math.ceil((result?.vulnerabilities?.length || 0) / VULNS_PER_PAGE);

  return (
    <div className="container">
      <div className="scanner">
        <div className="header-section">
          <h1>Container Security Scanner</h1>
          <p className="subtitle">Scan Docker images for vulnerabilities using Trivy</p>
          
          {trivyStatus && (
            <div className={`trivy-status ${trivyStatus.installed ? 'ready' : 'error'}`}>
              {trivyStatus.installed ? (
                <>
                  <span className="status-icon">✓</span>
                  <span>{trivyStatus.version}</span>
                </>
              ) : (
                <>
                  <span className="status-icon">✗</span>
                  <span>Trivy not available</span>
                </>
              )}
            </div>
          )}

          <button className="stats-btn" onClick={() => setShowStats(!showStats)}>
            📊 Cache Stats
          </button>
        </div>

        {showStats && cacheStats && (
          <div className="cache-stats-box">
            <h3>Cache Statistics</h3>
            <div className="stats-grid">
              <div className="stat-card">
                <div className="stat-value">{cacheStats.memory_cache_entries}</div>
                <div className="stat-label">Memory Cache</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">{cacheStats.database_cache_entries}</div>
                <div className="stat-label">Database Cache</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">{cacheStats.total_scans_history}</div>
                <div className="stat-label">Total Scans</div>
              </div>
              <div className="stat-card">
                <div className="stat-value">{cacheStats.average_vulns_per_scan}</div>
                <div className="stat-label">Avg Vulns/Scan</div>
              </div>
            </div>
            {cacheStats.recent_scans && cacheStats.recent_scans.length > 0 && (
              <div className="recent-scans">
                <h4>Recent Scans</h4>
                <ul>
                  {cacheStats.recent_scans.map((scan, idx) => (
                    <li key={idx}>{scan.image} • {new Date(scan.time).toLocaleString()}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        <form onSubmit={handleScan} className="scan-form">
          <input
            type="text"
            value={image}
            onChange={(e) => setImage(e.target.value)}
            placeholder="e.g., nginx:latest, ubuntu:16.04, python:3.9-slim"
            className="input-field"
            disabled={loading}
          />
          <button type="submit" disabled={loading} className="scan-btn">
            {loading ? (
              <>
                <span className="spinner"></span>
                Scanning...
              </>
            ) : (
              'Scan Image'
            )}
          </button>
        </form>

        {error && (
          <div className="error-box">
            <span className="error-icon">⚠</span>
            <span>{error}</span>
          </div>
        )}

        {result && (
          <div className="results">
            {result.warning && (
              <div className="warning-box">
                <span className="warning-icon">⚠️</span>
                <span>{result.warning}</span>
              </div>
            )}
            
            <div className="result-header">
              <div>
                <h2>Scan Results</h2>
                {cached && cacheAge !== null && (
                    <span className="cache-badge">
                        📦 Cached {cacheAge}h ago
                    </span>
                )}
                {cached && result.cache_source && (
                    <span className="cache-source">
                        ({result.cache_source === 'memory' ? 'Memory' : 'Database'})
                    </span>
                )}
              </div>
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
              {result.summary.unknown > 0 && (
                <div className="summary-card unknown">
                  <div className="number">{result.summary.unknown}</div>
                  <div className="label">UNKNOWN</div>
                </div>
              )}
            </div>

            {result.vulnerabilities.length > 0 ? (
              <div className="vulnerabilities-list">
                <h3>Found {result.vulnerabilities.length} Vulnerabilities</h3>
                <div className="filter-info">
                  Showing {startIdx + 1}-{Math.min(endIdx, result.vulnerabilities.length)} of {result.vulnerabilities.length} • Sorted by severity
                </div>

                {paginatedVulns.map((vuln, idx) => (
                  <div key={idx} className="vulnerability-item" style={{borderLeftColor: getSeverityColor(vuln.severity)}}>
                    <div className="vuln-header">
                      <span className="severity-badge" style={{backgroundColor: getSeverityColor(vuln.severity)}}>
                        {vuln.severity}
                      </span>
                      <span className="vuln-id">{vuln.id}</span>
                      {vuln.published_date && (
                        <span className="vuln-date">{formatDate(vuln.published_date)}</span>
                      )}
                    </div>
                    <h4>{vuln.title || 'Untitled Vulnerability'}</h4>
                    {vuln.description && (
                      <p className="description">{vuln.description}</p>
                    )}
                    <div className="vuln-details">
                      <div className="detail">
                        <strong>Package:</strong> {vuln.package} {vuln.version && `(${vuln.version})`}
                      </div>
                      {vuln.fixed_version && (
                        <div className="detail">
                          <strong>Fixed Version:</strong> {vuln.fixed_version}
                        </div>
                      )}
                      {vuln.source && (
                        <div className="detail">
                          <strong>Source:</strong> {vuln.source.toUpperCase()}
                        </div>
                      )}
                      {vuln.cvss && (
                        <div className="detail">
                          <strong>CVSS:</strong> {JSON.stringify(vuln.cvss)}
                        </div>
                      )}
                      {vuln.cwe && vuln.cwe.length > 0 && (
                        <div className="detail">
                          <strong>CWE:</strong> {vuln.cwe.join(', ')}
                        </div>
                      )}
                      {vuln.references && vuln.references.length > 0 && (
                        <div className="detail references">
                          <strong>References:</strong>
                          <div className="ref-list">
                            {vuln.references.map((ref, i) => (
                              <a key={i} href={ref} target="_blank" rel="noopener noreferrer" className="ref-link">
                                {ref.replace('https://', '').replace('http://', '').split('/')[0]}
                              </a>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                ))}

                {totalPages > 1 && (
                  <div className="pagination">
                    <button 
                      onClick={() => setCurrentPage(p => Math.max(1, p - 1))} 
                      disabled={currentPage === 1}
                      className="pagination-btn"
                    >
                      ← Previous
                    </button>
                    <span className="page-info">
                      Page {currentPage} of {totalPages}
                    </span>
                    <button 
                      onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} 
                      disabled={currentPage === totalPages}
                      className="pagination-btn"
                    >
                      Next →
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <div className="success-box">
                ✓ No vulnerabilities found!
              </div>
            )}
          </div>
        )}

        <div className="footer-info">
          <p>💡 <strong>Tip:</strong> First scan takes 30-90s. Repeated scans cached for 1 hour and return in 500ms.</p>
          <p>📊 Supports all registries: Docker Hub, ECR, GCR, custom registries • 📦 Persistent cache across restarts</p>
        </div>
      </div>
    </div>
  );
}

export default App;
