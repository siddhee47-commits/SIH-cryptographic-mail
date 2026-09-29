import { useRef, useState } from "react";

export default function PcapUpload({ onAnalyze, loading }) {
  const inputRef = useRef(null);
  const [file, setFile] = useState(null);

  function selectFile(event) {
    const selected = event.target.files?.[0];
    setFile(selected || null);
  }

  function submit(event) {
    event.preventDefault();

    if (file) {
      onAnalyze(file);
    }
  }

  return (
    <section className="card upload-card">
      <div>
        <h2>Analyze a PCAP</h2>

        <p className="muted">
          Upload an email-traffic capture in PCAP or PCAPNG format.
        </p>
      </div>

      <form onSubmit={submit}>
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
          onChange={selectFile}
          hidden
        />

        <button
          type="button"
          className="secondary-btn"
          onClick={() => inputRef.current?.click()}
        >
          Choose PCAP
        </button>

        <span className="file-name">
          {file ? file.name : "No file selected"}
        </span>

        <button
          type="submit"
          className="primary-btn"
          disabled={!file || loading}
        >
          {loading ? "Analyzing..." : "Analyze PCAP"}
        </button>
      </form>
    </section>
  );
}