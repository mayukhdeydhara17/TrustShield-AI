
import "./ScanResult.css";

function ScanResult({ result }) {
  if (!result) return null;

  return (
    <div className="result-container">

      <h2>Website Security Report</h2>

      <div className="risk-card">
        <p>Website Risk Score</p>

        <h1>{result.score}/100</h1>

        <span className="risk-level">
          {result.level} RISK
        </span>
      </div>

      <div className="security-details">

        <div className="security-item">
          <h3>Phishing Detection</h3>
          <p>{result.phishing}</p>
        </div>

        <div className="security-item">
          <h3>SSL Certificate</h3>
          <p>{result.ssl}</p>
        </div>

        <div className="security-item">
          <h3>Website Security</h3>
          <p>{result.security}</p>
        </div>

      </div>

      <div className="explanation">
        <h3>Analysis Explanation</h3>
        <p>{result.explanation}</p>
      </div>

    </div>
  );
}

export default ScanResult;
