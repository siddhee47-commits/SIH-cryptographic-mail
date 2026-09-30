WEAK_TLS_VERSIONS = {
    "TLS 1.0": "HIGH",
    "TLS 1.1": "HIGH",
    "SSLv3": "CRITICAL",
    "SSLv2": "CRITICAL"
}

WEAK_CIPHERS = {
    "3DES": "HIGH",
    "DES": "HIGH",
    "RC4": "HIGH",
    "NULL": "CRITICAL",
    "EXPORT": "CRITICAL"
}

WEAK_KEY_SIZES = {
    "RSA": 2048,
    "DSA": 2048,
    "EC": 256
}


def check_tls_version(version):
    if not version:
        return None

    if version in WEAK_TLS_VERSIONS:
        return {
            "severity": WEAK_TLS_VERSIONS[version],
            "type": "WEAK_TLS_VERSION",
            "message": f"Deprecated TLS version detected: {version}",
            "recommendation": "Use TLS 1.2 or TLS 1.3."
        }

    return None


def check_cipher(cipher):
    if not cipher:
        return None

    upper = cipher.upper()

    for weak_cipher, severity in WEAK_CIPHERS.items():
        if weak_cipher in upper:
            return {
                "severity": severity,
                "type": "WEAK_CIPHER",
                "message": f"Weak or deprecated cipher detected: {cipher}",
                "recommendation": "Use modern AEAD cipher suites such as AES-GCM or ChaCha20-Poly1305."
            }

    return None


def check_forward_secrecy(key_exchange, forward_secrecy):
    if forward_secrecy is False:
        return {
            "severity": "MEDIUM",
            "type": "NO_FORWARD_SECRECY",
            "message": f"Forward Secrecy is not provided by key exchange: {key_exchange}",
            "recommendation": "Use ECDHE or another forward-secret key exchange."
        }

    return None
