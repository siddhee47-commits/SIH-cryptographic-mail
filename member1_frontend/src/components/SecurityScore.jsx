export default function SecurityScore({ score }) {
  return (
    <div className="card score-card">
      <p className="label">
        Security posture score
      </p>

      <div className="score">
        {score}
        <span>/100</span>
      </div>

      <p className="muted">
        Final scoring can be supplied by the M5 risk engine.
      </p>
    </div>
  );
}