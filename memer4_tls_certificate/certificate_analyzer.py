def analyze_certificate(certificate):
    if not certificate:
        return {
            "certificate_observed": False,
            "certificate": None,
            "findings": []
        }

    findings = []

    if certificate.get("expired", False):
        findings.append({
            "severity": "HIGH",
            "type": "EXPIRED_CERTIFICATE",
            "message": "The X.509 certificate is expired.",
            "recommendation": "Renew the certificate before its validity period ends."
        })

    if certificate.get("chain_valid") is False:
        findings.append({
            "severity": "HIGH",
            "type": "INVALID_CERTIFICATE_CHAIN",
            "message": "Certificate chain validation failed.",
            "recommendation": "Install a valid certificate chain issued by a trusted CA."
        })

    key_algorithm = certificate.get("public_key_algorithm")
    key_bits = certificate.get("public_key_bits")

    if key_algorithm and key_bits:
        if key_algorithm.upper() == "RSA" and key_bits < 2048:
            findings.append({
                "severity": "HIGH",
                "type": "WEAK_PUBLIC_KEY",
                "message": f"RSA public key is only {key_bits} bits.",
                "recommendation": "Use RSA keys of at least 2048 bits."
            })

    signature_algorithm = certificate.get(
        "signature_algorithm", ""
    ).upper()

    if "SHA1" in signature_algorithm or "SHA-1" in signature_algorithm:
        findings.append({
            "severity": "HIGH",
            "type": "WEAK_SIGNATURE_ALGORITHM",
            "message": "Certificate uses the deprecated SHA-1 signature algorithm.",
            "recommendation": "Use a certificate signed with SHA-256 or stronger."
        })

    return {
        "certificate_observed": True,
        "certificate": certificate,
        "findings": findings
    }
