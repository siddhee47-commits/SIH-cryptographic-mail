class CertificateAnalyzer:

    def analyze(self, certificate):

        findings = []

        subject = certificate.get("subject", "Unknown")
        issuer = certificate.get("issuer", "Unknown")
        valid_from = certificate.get("valid_from", "Unknown")
        valid_to = certificate.get("valid_to", "Unknown")

        expired = certificate.get("expired", False)
        chain_valid = certificate.get("chain_valid", False)

        public_key_algorithm = certificate.get(
            "public_key_algorithm", "Unknown"
        )

        public_key_bits = certificate.get(
            "public_key_bits", 0
        )

        signature_algorithm = certificate.get(
            "signature_algorithm", "Unknown"
        )

        # Check certificate expiry
        if expired:
            findings.append({
                "type": "CERTIFICATE_EXPIRED",
                "severity": "HIGH",
                "message": "The X.509 certificate has expired."
            })

        # Check certificate chain
        if not chain_valid:
            findings.append({
                "type": "INVALID_CERTIFICATE_CHAIN",
                "severity": "HIGH",
                "message": "The certificate chain could not be validated."
            })

        # Check public key size
        if public_key_bits and public_key_bits < 2048:
            findings.append({
                "type": "WEAK_PUBLIC_KEY",
                "severity": "HIGH",
                "message": (
                    f"Certificate public key size is only "
                    f"{public_key_bits} bits."
                )
            })

        return {
            "subject": subject,
            "issuer": issuer,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "expired": expired,
            "chain_valid": chain_valid,
            "public_key_algorithm": public_key_algorithm,
            "public_key_bits": public_key_bits,
            "signature_algorithm": signature_algorithm,
            "findings": findings
        }