
import { useState, useEffect } from "react";
import "./App.css";
import ScanResult from "./components/ScanResult";
import { scanWebsite } from "./services/scanApi";

const API_URL = import.meta.env.VITE_API_URL;

function App() {
  const [scanHistory, setScanHistory] = useState(() => {
    try {
      return JSON.parse(
        localStorage.getItem("trustshield_scan_history") || "[]"
      );
    } catch {
      return [];
    }
  });
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [backendStatus, setBackendStatus] = useState("Checking...");

  // Check backend connection
  useEffect(() => {
    fetch(`${API_URL}/health`)
      .then((response) => {
        if (!response.ok) {
          throw new Error("Backend unavailable");
        }
        return response.json();
      })
      .then((data) => {
        setBackendStatus(
          data.status === "healthy" ? "Connected" : "Unavailable"
        );
      })
      .catch(() => {
        setBackendStatus("Disconnected");
      });
  }, []);

  // Scan website
  async function handleScan() {
    if (!url.trim()) {
      setError("Please enter a website URL.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const data = await scanWebsite(url.trim());
      const newScan = {
        id: Date.now(),
        url: url.trim(),
        riskScore: data.risk_score,
        riskLevel: data.risk_level,
        scannedAt: new Date().toLocaleString(),
      };

      setScanHistory((previous) => {
        const updated = [newScan, ...previous].slice(0, 10);

        localStorage.setItem(
          "trustshield_scan_history",
          JSON.stringify(updated)
        );

        return updated;
      });

      setResult({
        score: data.risk_score,
        level: data.risk_level,
        phishing: data.phishing_detected
          ? "Suspicious"
          : "No phishing detected",
        ssl:
          data.ssl_valid === null
            ? "Unknown"
            : data.ssl_valid
              ? "Valid"
              : "Invalid",
        security: data.security_status,
        explanation: data.explanation,
      });

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">

      <nav className="navbar">
        <h2>🛡️ TrustShield AI</h2>
        <p>Backend: {backendStatus}</p>
      </nav>
      <section className="stats-section">

        <div className="stat-card">
          <h3>Total Scans</h3>
          <h2>{scanHistory.length}</h2>
        </div>

        <div className="stat-card">
          <h3>Suspicious Websites</h3>
          <h2>
            {scanHistory.filter(
              scan => scan.riskLevel === "High"
            ).length}
          </h2>
        </div>

        <div className="stat-card">
          <h3>Low Risk Websites</h3>
          <h2>
            {scanHistory.filter(
              scan => scan.riskLevel === "Low"
            ).length}
          </h2>
        </div>

      </section>
      <main className="hero">

        <p className="tagline">
          YOUR DIGITAL SAFETY STARTS HERE
        </p>

        <h1>
          Don't Trust Every Link.
          <br />
          <span>Verify It First.</span>
        </h1>

        <p className="description">
          Analyze website security, identify suspicious URLs
          and understand potential online threats.
        </p>

        <div className="scanner">

          <input
            type="text"
            placeholder="Enter website URL..."
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              setResult(null);
              setError("");
            }}
          />

          <button
            onClick={handleScan}
            disabled={loading}
          >
            {loading ? "Scanning..." : "Scan Website"}
          </button>

        </div>

        {loading && (
          <p className="note">
            Analyzing website security...
          </p>
        )}

        {error && (
          <p className="error-message">
            {error}
          </p>
        )}

        <p className="note">
          Stay alert. Stay protected.
        </p>

      </main>

      <ScanResult result={result} />
      <section className="history-section">
        <h2>Recent Scan History</h2>

        {scanHistory.length === 0 ? (
          <p>No previous scans yet.</p>
        ) : (
          scanHistory.map((scan) => (
            <div className="history-card" key={scan.id}>
              <div>
                <h3>{scan.url}</h3>
                <small>{scan.scannedAt}</small>
              </div>

              <div>
                <strong>{scan.riskScore}/100</strong>
                <p>{scan.riskLevel}</p>
              </div>
            </div>
          ))
        )}
      </section>

    </div>
  );
}

export default App;
