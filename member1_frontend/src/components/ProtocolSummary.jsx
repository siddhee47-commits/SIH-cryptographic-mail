export default function ProtocolSummary({ data }) {
  const protocols = data.protocols || data.protocol || [];

  const protocolList = Array.isArray(protocols)
    ? protocols
    : [protocols].filter(Boolean);

  return (
    <div className="card">
      <p className="label">
        Protocol & TLS summary
      </p>

      <div className="summary-list">
        <div>
          <span>Email protocols</span>
          <strong>
            {protocolList.length
              ? protocolList.join(", ")
              : "—"}
          </strong>
        </div>

        <div>
          <span>STARTTLS</span>
          <strong>
            {formatBool(data.starttls_detected)}
          </strong>
        </div>

        <div>
          <span>TLS version</span>
          <strong>
            {data.tls_version || "—"}
          </strong>
        </div>

        <div>
          <span>Cipher suite</span>
          <strong>
            {data.cipher_suite || "—"}
          </strong>
        </div>

        <div>
          <span>Key exchange</span>
          <strong>
            {data.key_exchange || "—"}
          </strong>
        </div>

        <div>
          <span>Forward Secrecy</span>
          <strong>
            {formatBool(data.forward_secrecy)}
          </strong>
        </div>
      </div>
    </div>
  );
}

function formatBool(value) {
  if (value === true) return "Enabled";
  if (value === false) return "Disabled";
  return "—";
}
