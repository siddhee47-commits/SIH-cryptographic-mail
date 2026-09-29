import SecurityScore from "./SecurityScore";
import ProtocolSummary from "./ProtocolSummary";
import FindingsTable from "./FindingsTable";

export default function Dashboard({ data }) {
  const score = data.security_score ?? data.risk_score ?? 0;
  const findings = data.findings || [];

  return (
    <section className="dashboard">
      <div className="section-heading">
        <div>
          <p className="eyebrow">Assessment result</p>
          <h2>Security Posture Dashboard</h2>
        </div>

        <span className="status-pill">
          {data.status || "Analysis complete"}
        </span>
      </div>

      <div className="dashboard-grid">
        <SecurityScore score={score} />
        <ProtocolSummary data={data} />
      </div>

      <FindingsTable findings={findings} />

      <details className="raw-data">
        <summary>View raw JSON</summary>

        <pre>
          {JSON.stringify(data, null, 2)}
        </pre>
      </details>
    </section>
  );
}