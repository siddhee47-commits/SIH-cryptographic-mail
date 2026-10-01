from ml_predictor import predict_risk


test_cases = [
    {
        "name": "Safe Connection",
        "features": {
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "weak_tls_version": 0,
            "weak_cipher": 0,
            "no_forward_secrecy": 0,
            "weak_public_key": 0,
            "expired_certificate": 0,
            "invalid_certificate_chain": 0,
            "weak_signature_algorithm": 0,
            "starttls_missing": 0
        }
    },

    {
        "name": "Missing STARTTLS",
        "features": {
            "critical_findings": 0,
            "high_findings": 1,
            "medium_findings": 0,
            "weak_tls_version": 0,
            "weak_cipher": 0,
            "no_forward_secrecy": 0,
            "weak_public_key": 0,
            "expired_certificate": 0,
            "invalid_certificate_chain": 0,
            "weak_signature_algorithm": 0,
            "starttls_missing": 1
        }
    },

    {
        "name": "Medium TLS Weakness",
        "features": {
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 1,
            "weak_tls_version": 1,
            "weak_cipher": 0,
            "no_forward_secrecy": 0,
            "weak_public_key": 0,
            "expired_certificate": 0,
            "invalid_certificate_chain": 0,
            "weak_signature_algorithm": 0,
            "starttls_missing": 0
        }
    },

    {
        "name": "Critical Security Issue",
        "features": {
            "critical_findings": 1,
            "high_findings": 0,
            "medium_findings": 0,
            "weak_tls_version": 0,
            "weak_cipher": 0,
            "no_forward_secrecy": 0,
            "weak_public_key": 0,
            "expired_certificate": 0,
            "invalid_certificate_chain": 0,
            "weak_signature_algorithm": 0,
            "starttls_missing": 0
        }
    }
]


for case in test_cases:

    result = predict_risk(case["features"])

    print("------------------------------")
    print("Test:", case["name"])
    print("ML Prediction:", result)