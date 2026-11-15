import Navbar from "./components/Navbar";
import { useState, useEffect, lazy, Suspense } from "react";
import "./App.css";
import ScanResult from "./components/ScanResult";
import { scanWebsite } from "./services/scanApi";
import Dashboard from "./components/Dashboard";
import ScanHistory from "./components/ScanHistory";
import RiskChart from "./components/RiskChart";
const CyberBackground = lazy(() => import("./components/CyberBackground"));
const ThreatBackdrop = lazy(() => import("./components/ThreatBackdrop"));
import LiveDemo from "./components/LiveDemo";
import SignIn from "./components/SignIn";
import { EvidenceGraph, Story, Steps, Views, Cases, Cta, Footer } from "./components/Landing";

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

  // simple hash route: #/sign-in shows the login page
  const [route, setRoute] = useState(window.location.hash);
  useEffect(() => {
    const on = () => setRoute(window.location.hash);
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);

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
        scannedAt: new Date().toISOString(),
      };

      setScanHistory((previous) => {
        const updated = [newScan, ...previous];

        localStorage.setItem(
          "trustshield_scan_history",
          JSON.stringify(updated)
        );

        return updated;
      });

      setResult({
        url: url.trim(),
        scannedAt: new Date().toLocaleString(),
        score: data.risk_score,
        level: data.risk_level,
        phishing: data.phishing_detected
          ? "Suspicious"
          : "No phishing detected",

        ssl: data.ssl_valid === null
          ? "Unknown"
          : data.ssl_valid
            ? "Valid"
            : "Invalid",

        sslDetails: data.ssl_details,
        websiteSecurity: data.website_security,

        security: data.security_status,
        explanation: data.explanation,
      });

    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  if (route === "#/sign-in") return <SignIn />;

  return (
    <div className="app" id="top">
      <Suspense fallback={null}>
        <CyberBackground />
        <ThreatBackdrop />
      </Suspense>
      <Navbar backendStatus={backendStatus} />

      <main className="hero">
        <p className="tagline">YOUR DIGITAL SAFETY STARTS HERE</p>

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
            onKeyDown={(e) => e.key === "Enter" && !loading && handleScan()}
          />
          <button onClick={handleScan} disabled={loading}>
            {loading ? "Scanning..." : "Scan Website"}
          </button>
        </div>

        {loading && <p className="note">Analyzing website security...</p>}
        {error && <p className="error-message">{error}</p>}
        <p className="note">Passive checks. Stay alert. Stay protected.</p>

        <EvidenceGraph />
      </main>

      <ScanResult result={result} />

      <LiveDemo />

      <Story />
      <Steps />
      <Views />
      <Cases />

      <div id="history">
        <Dashboard history={scanHistory} />
        <RiskChart history={scanHistory} />
        <ScanHistory history={scanHistory} />
      </div>

      <Cta />
      <Footer />
    </div>
  );
}

export default App;
