import Navbar from "./components/Navbar";
import { useState, useEffect, lazy, Suspense } from "react";
import "./App.css";
import ScanResult from "./components/ScanResult";
import { scanWebsite, fetchScanHistory } from "./services/scanApi";
import Dashboard from "./components/Dashboard";
import ScanHistory from "./components/ScanHistory";
import RiskChart from "./components/RiskChart";
const CyberBackground = lazy(() => import("./components/CyberBackground"));
const ThreatBackdrop = lazy(() => import("./components/ThreatBackdrop"));
import LiveDemo from "./components/LiveDemo";
import SignIn from "./components/SignIn";
import { EvidenceGraph, Story, Steps, Views, Cases, Cta, Footer } from "./components/Landing";

const API_URL = (import.meta.env.VITE_API_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

function App() {
  const [scanHistory, setScanHistory] = useState([]);
  const [account, setAccount] = useState(null);
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

  // Validate the saved session and load history belonging only to that account.
  useEffect(() => {
    let cancelled = false;
    async function loadAccount() {
      const token = localStorage.getItem("trustshield_access_token");
      if (!token) {
        setAccount(null);
        setScanHistory([]);
        return;
      }
      try {
        const response = await fetch(`${API_URL}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!response.ok) throw new Error("Session expired");
        const user = await response.json();
        const history = await fetchScanHistory(token);
        if (!cancelled) {
          setAccount(user);
          setScanHistory(history);
          localStorage.setItem("trustshield_user", JSON.stringify(user));
        }
      } catch {
        localStorage.removeItem("trustshield_access_token");
        localStorage.removeItem("trustshield_user");
        if (!cancelled) {
          setAccount(null);
          setScanHistory([]);
        }
      }
    }
    loadAccount();
    return () => { cancelled = true; };
  }, [route]);

  async function handleLogout() {
    const token = localStorage.getItem("trustshield_access_token");
    try {
      if (token) await fetch(`${API_URL}/auth/logout`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
    } finally {
      localStorage.removeItem("trustshield_access_token");
      localStorage.removeItem("trustshield_user");
      setAccount(null);
      setScanHistory([]);
      setResult(null);
      window.location.hash = "#/sign-in";
    }
  }

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
    const token = localStorage.getItem("trustshield_access_token");
    if (!account || !token) {
      setError("Please sign in to save scans to your personal history.");
      window.location.hash = "#/sign-in";
      return;
    }
    if (!url.trim()) {
      setError("Please enter a website URL.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const data = await scanWebsite(url.trim(), token);
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

      // The POST /scan response means the backend completed and saved the scan.
      // Refresh history separately so a history-fetch error does not hide the result.
      try {
        const savedHistory = await fetchScanHistory(token);
        setScanHistory(savedHistory);
      } catch (historyError) {
        setError(`Scan completed, but history could not be refreshed: ${historyError.message}`);
      }

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
      <Navbar backendStatus={backendStatus} account={account} onLogout={handleLogout} />

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
        {!account && <p className="note">Sign in to scan websites and save your scan history to your account.</p>}

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
