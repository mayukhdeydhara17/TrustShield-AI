import { useState } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");

  function handleScan() {
    if (!url.trim()) {
      alert("Please enter a website URL");
      return;
    }

    alert("URL received: " + url);
  }

  return (
    <div className="app">
      <nav className="navbar">
        <h2>🛡️ TrustShield AI</h2>
        <p>Website Security Analyzer</p>
      </nav>

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
            onChange={(e) => setUrl(e.target.value)}
          />

          <button onClick={handleScan}>
            Scan Website
          </button>
        </div>

        <p className="note">Stay alert. Stay protected.</p>
      </main>
    </div>
  );
}

export default App;