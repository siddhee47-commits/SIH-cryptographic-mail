from tls_analyzer import analyze_tls
from certificate_analyzer import analyze_certificate


def analyze_stream(stream):
    protocol = stream.get("protocol", "UNKNOWN")
    starttls = stream.get("starttls_detected", False)

    tls_data = stream.get("tls", {})
    certificate_data = stream.get("certificate", {})

    findings = []

    # STARTTLS security check
    if protocol in ["SMTP", "IMAP", "POP3"] and not starttls:
        findings.append({
            "severity": "HIGH",
            "type": "NO_STARTTLS",
            "message": f"{protocol} stream does not show STARTTLS.",
            "recommendation": "Use TLS/STARTTLS for email communication."
        })

    # TLS analysis
    tls_result = analyze_tls(tls_data)
    findings.extend(tls_result["findings"])

    # Certificate analysis
    certificate_result = analyze_certificate(certificate_data)
    findings.extend(certificate_result["findings"])

    return {
        "stream_id": stream.get("stream_id"),
        "protocol": protocol,
        "starttls_detected": starttls,

        "tls": {
            "observed": tls_result["tls_observed"],
            "tls_version": tls_result["tls_version"],
            "cipher_suite": tls_result["cipher_suite"],
            "key_exchange": tls_result["key_exchange"],
            "forward_secrecy": tls_result["forward_secrecy"]
        },

        "certificate": {
            "observed": certificate_result["certificate_observed"],
            "details": certificate_result["certificate"]
        },

        "findings": findings
    }


def analyze(m3_data):
    return {
        "module": "M4 - TLS and Certificate Analysis",
        "streams_analyzed": len(m3_data),
        "results": [
            analyze_stream(stream)
            for stream in m3_data
        ]
    }
