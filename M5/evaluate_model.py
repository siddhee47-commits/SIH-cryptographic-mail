from ml_predictor import predict_risk


test_cases = [
    {
        "name": "Safe Connection",
        "expected": "LOW",
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
        "name": "Medium Weak TLS",
        "expected": "MEDIUM",
        "features": {
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
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
        "name": "High Missing STARTTLS",
        "expected": "HIGH",
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
        "name": "Critical Finding",
        "expected": "CRITICAL",
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
    },
    {
        "name": "Expired Certificate",
        "expected": "HIGH",
        "features": {
            "critical_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "weak_tls_version": 0,
            "weak_cipher": 0,
            "no_forward_secrecy": 0,
            "weak_public_key": 0,
            "expired_certificate": 1,
            "invalid_certificate_chain": 0,
            "weak_signature_algorithm": 0,
            "starttls_missing": 0
        }
    },
    {
        "name": "Multiple Critical Issues",
        "expected": "CRITICAL",
        "features": {
            "critical_findings": 1,
            "high_findings": 1,
            "medium_findings": 1,
            "weak_tls_version": 1,
            "weak_cipher": 1,
            "no_forward_secrecy": 1,
            "weak_public_key": 1,
            "expired_certificate": 1,
            "invalid_certificate_chain": 1,
            "weak_signature_algorithm": 1,
            "starttls_missing": 1
        }
    }
]


correct = 0

print("================================")
print("M5 ML Model Evaluation")
print("================================")

for case in test_cases:

    predicted = predict_risk(case["features"])

    if predicted == case["expected"]:
        correct += 1
        status = "PASS"
    else:
        status = "FAIL"

    print("------------------------------")
    print("Test:", case["name"])
    print("Expected:", case["expected"])
    print("Predicted:", predicted)
    print("Result:", status)


accuracy = (correct / len(test_cases)) * 100

print("------------------------------")
print("Correct:", correct, "/", len(test_cases))
print(f"Test Accuracy: {accuracy:.2f}%")