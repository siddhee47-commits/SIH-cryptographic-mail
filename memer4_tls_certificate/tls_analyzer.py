from tls_rules import (
    check_tls_version,
    check_cipher,
    check_key_exchange,
    check_forward_secrecy
)


class TLSAnalyzer:

    def analyze(self, session):

        findings = []

        tls_version = session.get("tls_version", "Unknown")
        cipher_suite = session.get("cipher_suite", "Unknown")
        key_exchange = session.get("key_exchange", "Unknown")
        forward_secrecy = session.get("forward_secrecy", False)

        starttls_detected = session.get("starttls_detected", False)
        handshake_detected = session.get("handshake_detected", False)

        # Check TLS version
        finding = check_tls_version(tls_version)
        if finding:
            findings.append(finding)

        # Check cipher suite
        finding = check_cipher(cipher_suite)
        if finding:
            findings.append(finding)

        # Check key exchange
        finding = check_key_exchange(key_exchange)
        if finding:
            findings.append(finding)

        # Check Forward Secrecy
        finding = check_forward_secrecy(forward_secrecy, key_exchange)
        if finding:
            findings.append(finding)

        return {
            "tls_version": tls_version,
            "cipher_suite": cipher_suite,
            "key_exchange": key_exchange,
            "starttls_detected": starttls_detected,
            "handshake_detected": handshake_detected,
            "forward_secrecy": forward_secrecy,
            "findings": findings
        }