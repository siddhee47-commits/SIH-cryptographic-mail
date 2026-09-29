# Deprecated TLS versions
DEPRECATED_TLS_VERSIONS = {
    "SSLv2",
    "SSLv3",
    "TLSv1",
    "TLS1.0",
    "TLSv1.0",
    "TLS1.1",
    "TLSv1.1"
}


# Cipher components considered weak
WEAK_CIPHER_PATTERNS = {
    "RC4",
    "3DES",
    "DES",
    "NULL",
    "EXPORT"
}


# Key exchange mechanisms that do not provide Forward Secrecy
WEAK_KEY_EXCHANGE = {
    "RSA",
    "DH",
    "STATIC-DH"
}


def check_tls_version(tls_version):

    if tls_version in DEPRECATED_TLS_VERSIONS:
        return {
            "type": "DEPRECATED_TLS_VERSION",
            "severity": "HIGH",
            "message": f"Deprecated TLS version detected: {tls_version}"
        }

    return None


def check_cipher(cipher_suite):

    cipher_upper = cipher_suite.upper()

    for weak_cipher in WEAK_CIPHER_PATTERNS:

        if weak_cipher in cipher_upper:
            return {
                "type": "WEAK_CIPHER_SUITE",
                "severity": "HIGH",
                "message": (
                    f"Weak or deprecated cipher component detected: "
                    f"{weak_cipher}"
                )
            }

    return None


def check_key_exchange(key_exchange):

    key_exchange_upper = key_exchange.upper()

    for weak_exchange in WEAK_KEY_EXCHANGE:

        if key_exchange_upper == weak_exchange:
            return {
                "type": "WEAK_KEY_EXCHANGE",
                "severity": "MEDIUM",
                "message": (
                    f"Key exchange mechanism does not provide "
                    f"Forward Secrecy: {key_exchange}"
                )
            }

    return None


def check_forward_secrecy(forward_secrecy, key_exchange):

    if not forward_secrecy:

        return {
            "type": "NO_FORWARD_SECRECY",
            "severity": "MEDIUM",
            "message": (
                f"Forward Secrecy is not enabled. "
                f"Key exchange: {key_exchange}"
            )
        }

    return None