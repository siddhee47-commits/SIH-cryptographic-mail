from member4_engine import analyze

test_data = [
    {
        "stream_id": "TEST-TLS-WEAK",
        "protocol": "SMTP",
        "starttls_detected": True,

        "tls": {
            "tls_version": "TLS 1.0",
            "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "key_exchange": "RSA",
            "forward_secrecy": False
        },

        "certificate": {
            "subject": "CN=mail.example.com",
            "issuer": "Example CA",
            "expired": True,
            "chain_valid": False,
            "public_key_algorithm": "RSA",
            "public_key_bits": 1024,
            "signature_algorithm": "sha1WithRSAEncryption"
        }
    }
]

result = analyze(test_data)

import json
print(json.dumps(result, indent=4))
