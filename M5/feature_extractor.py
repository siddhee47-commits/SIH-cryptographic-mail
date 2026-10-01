def extract_features(stream):
    """
    Convert one M4 stream result into numerical features
    for the M5 risk engine.
    """

    tls = stream.get("tls", {})
    certificate = stream.get("certificate", {})
    findings = stream.get("findings", [])

    features = {
        "starttls_missing": 0,
        "tls_observed": 0,
        "certificate_observed": 0,

        "high_findings": 0,
        "medium_findings": 0,
        "critical_findings": 0,

        "weak_tls_version": 0,
        "weak_cipher": 0,
        "no_forward_secrecy": 0,
        "weak_public_key": 0,
        "expired_certificate": 0,
        "invalid_certificate_chain": 0,
        "weak_signature_algorithm": 0
    }

    # STARTTLS
    if (
        stream.get("protocol") in ["SMTP", "IMAP", "POP3"]
        and stream.get("starttls_detected") is False
    ):
        features["starttls_missing"] = 1

    # TLS observed
    if tls.get("observed") is True:
        features["tls_observed"] = 1

    # Certificate observed
    if certificate.get("observed") is True:
        features["certificate_observed"] = 1

    # Analyze M4 findings
    for finding in findings:
        severity = finding.get("severity", "")
        finding_type = finding.get("type", "")

        if severity == "HIGH":
            features["high_findings"] += 1

        elif severity == "MEDIUM":
            features["medium_findings"] += 1

        elif severity == "CRITICAL":
            features["critical_findings"] += 1

        if finding_type == "WEAK_TLS_VERSION":
            features["weak_tls_version"] = 1

        elif finding_type == "WEAK_CIPHER":
            features["weak_cipher"] = 1

        elif finding_type == "NO_FORWARD_SECRECY":
            features["no_forward_secrecy"] = 1

        elif finding_type == "WEAK_PUBLIC_KEY":
            features["weak_public_key"] = 1

        elif finding_type == "EXPIRED_CERTIFICATE":
            features["expired_certificate"] = 1

        elif finding_type == "INVALID_CERTIFICATE_CHAIN":
            features["invalid_certificate_chain"] = 1

        elif finding_type == "WEAK_SIGNATURE_ALGORITHM":
            features["weak_signature_algorithm"] = 1

    return features