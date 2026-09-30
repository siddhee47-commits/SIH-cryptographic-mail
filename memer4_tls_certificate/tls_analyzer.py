from tls_rules import (
    check_tls_version,
    check_cipher,
    check_forward_secrecy
)


def analyze_tls(tls):
    findings = []

    if not tls:
        return {
            "tls_observed": False,
            "tls_version": None,
            "cipher_suite": None,
            "key_exchange": None,
            "forward_secrecy": None,
            "findings": []
        }

    version = tls.get("tls_version")
    cipher = tls.get("cipher_suite")
    key_exchange = tls.get("key_exchange")
    forward_secrecy = tls.get("forward_secrecy")

    finding = check_tls_version(version)
    if finding:
        findings.append(finding)

    finding = check_cipher(cipher)
    if finding:
        findings.append(finding)

    finding = check_forward_secrecy(
        key_exchange,
        forward_secrecy
    )
    if finding:
        findings.append(finding)

    return {
        "tls_observed": True,
        "tls_version": version,
        "cipher_suite": cipher,
        "key_exchange": key_exchange,
        "forward_secrecy": forward_secrecy,
        "findings": findings
    }
