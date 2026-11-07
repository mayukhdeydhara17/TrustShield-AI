
function RiskChart({ history = [] }) {
  const safe = history.filter(
    (scan) => scan.riskLevel?.toLowerCase() === "low"
  ).length;

  const suspicious = history.filter(
    (scan) => scan.riskLevel?.toLowerCase() === "medium"
  ).length;

  const highRisk = history.filter(
    (scan) => scan.riskLevel?.toLowerCase() === "high"
  ).length;

  const total = history.length;

  const getPercentage = (value) => {
    return total === 0 ? 0 : (value / total) * 100;
  };

  const categories = [
    { name: "Safe", count: safe, color: "#22c55e" },
    { name: "Suspicious", count: suspicious, color: "#f59e0b" },
    { name: "High Risk", count: highRisk, color: "#ef4444" },
  ];

  return (
    <section className="risk-chart">
      <h2>Website Risk Overview</h2>

      {categories.map((category) => (
        <div className="risk-item" key={category.name}>
          <div className="risk-label">
            <span>{category.name}</span>
            <strong>{category.count}</strong>
          </div>

          <div className="risk-bar">
            <div
              className="risk-fill"
              style={{
                width: `${getPercentage(category.count)}%`,
                backgroundColor: category.color,
              }}
            />
          </div>
        </div>
      ))}

      <p>Total websites scanned: {total}</p>
    </section>
  );
}

export default RiskChart;
