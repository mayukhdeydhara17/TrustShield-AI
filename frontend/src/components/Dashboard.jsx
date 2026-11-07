
function Dashboard({ history = [] }) {
  const totalScans = history.length;

  const safeScans = history.filter(
    (scan) => scan.riskLevel?.toLowerCase() === "low"
  ).length;

  const suspiciousScans = history.filter(
    (scan) => scan.riskLevel?.toLowerCase() === "medium"
  ).length;

  const highRiskScans = history.filter(
    (scan) => scan.riskLevel?.toLowerCase() === "high"
  ).length;

  const stats = [
    { title: "Total Scans", value: totalScans },
    { title: "Safe Websites", value: safeScans },
    { title: "Suspicious Websites", value: suspiciousScans },
    { title: "High-Risk Websites", value: highRiskScans },
  ];

  return (
    <section className="dashboard">
      <h2>Security Dashboard</h2>

      <div className="dashboard-grid">
        {stats.map((stat) => (
          <div className="dashboard-card" key={stat.title}>
            <h3>{stat.title}</h3>
            <p>{stat.value}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

export default Dashboard;
