
import { useState } from "react";
import "./App.css";
import ScanResult from "./components/ScanResult";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);

  function handleScan() {
    if (!url.trim()) {
      alert("Please enter a website URL");
      return;
    }

    // Temporary demonstration data.
    // Actual backend integration comes later.

    setResult({
      score: 85,
      level: "HIGH",
      phishing: "Suspicious",
      ssl: "Invalid",
      security: "Issues Found",
      explanation:
        "This is a demonstration report. Actual security findings will come from our backend scanning engine."
    });
  }

  return (
    <div className="app">

      <nav className="navbar">
        <h2>🛡️ TrustShield AI</h2>
        <p>Website Security Analyzer</p>
      </nav>

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
            }}
          />

          <button onClick={handleScan}>
            Scan Website
          </button>

        </div>

        <p className="note">
          Stay alert. Stay protected.
        </p>

      </main>

      <ScanResult result={result} />

    </div>
  );
}

export default App;
