function ScanHistory({ history = [] }) {
  return (
    <section className="scan-history">
      <h2>Recent Scan History</h2>

      {history.length === 0 ? (
        <p>No scans yet. Start scanning a website!</p>
      ) : (
        <div className="history-list">
          {history.map((scan) => (
            <div className="history-item" key={scan.id}>
              <div>
                <h4>{scan.url}</h4>
                <small>
                  {new Date(scan.scannedAt).toLocaleString()}
                </small>
              </div>

              <div>
                <strong>{scan.riskLevel}</strong>
                <p>Risk Score: {scan.riskScore}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export default ScanHistory;
