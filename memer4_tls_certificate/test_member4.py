from member4_engine import Member4Engine


def test_secure_session():
    secure_data = {
        "tls": {
            "tls_version": "TLS 1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE",
            "starttls_detected": True,
            "handshake_detected": True,
            "forward_secrecy": True
        },
        "certificate": {
            "subject": "CN=mail.example.com",
            "issuer": "Example CA",
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": "2027-01-01T00:00:00Z",
            "expired": False,
            "public_key_algorithm": "RSA",
            "public_key_bits": 2048,
            "signature_algorithm": "sha256WithRSAEncryption",
            "chain_valid": True
        }
    }

    engine = Member4Engine()
    result = engine.analyze(secure_data)

    print("\n===== SECURE SESSION TEST =====")
    print(result)

    assert len(result["findings"]) == 0

    print("Secure session test PASSED")


def test_weak_session():
    weak_data = {
        "tls": {
            "tls_version": "TLS1.0",
            "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "key_exchange": "RSA",
            "starttls_detected": True,
            "handshake_detected": True,
            "forward_secrecy": False
        },
        "certificate": {
            "subject": "CN=old-mail.example.com",
            "issuer": "Old CA",
            "valid_from": "2020-01-01T00:00:00Z",
            "valid_to": "2021-01-01T00:00:00Z",
            "expired": True,
            "public_key_algorithm": "RSA",
            "public_key_bits": 1024,
            "signature_algorithm": "sha1WithRSAEncryption",
            "chain_valid": False
        }
    }

    engine = Member4Engine()
    result = engine.analyze(weak_data)

    print("\n===== WEAK SESSION TEST =====")
    print(result)

    assert len(result["findings"]) > 0

    print("Weak session test PASSED")


if __name__ == "__main__":
    test_secure_session()
    test_weak_session()

    print("\n===== ALL TESTS PASSED =====")