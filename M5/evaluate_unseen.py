from ml_predictor import predict_risk

ALL_FEATURES = [
    "critical_findings", "high_findings", "medium_findings",
    "weak_tls_version", "weak_cipher", "no_forward_secrecy",
    "weak_public_key", "expired_certificate",
    "invalid_certificate_chain", "weak_signature_algorithm",
    "starttls_missing",
]


def make_features(**kwargs):
    """Sab features 0 se start, jo dena hai sirf wahi set karo."""
    features = {name: 0 for name in ALL_FEATURES}
    features.update(kwargs)
    return features


# Ye combinations training_data.csv mein nahi hain
unseen_cases = [
    {
        "name": "High + Expired + No STARTTLS",
        "expected": "CRITICAL",
        "features": make_features(
            high_findings=1, expired_certificate=1, starttls_missing=1
        ),
    },
    {
        "name": "Medium + Weak TLS + Weak Cipher",
        "expected": "HIGH",
        "features": make_features(
            medium_findings=1, weak_tls_version=1, weak_cipher=1
        ),
    },
    {
        "name": "Expired Cert + No STARTTLS",
        "expected": "HIGH",
        "features": make_features(
            expired_certificate=1, starttls_missing=1
        ),
    },
]

correct = 0

print("================================")
print("M5 ML Evaluation - Unseen Cases")
print("================================")

for case in unseen_cases:
    predicted = predict_risk(case["features"])
    passed = predicted == case["expected"]
    if passed:
        correct += 1

    print("------------------------------")
    print("Test:", case["name"])
    print("Expected:", case["expected"])
    print("Predicted:", predicted)
    print("Result:", "PASS" if passed else "FAIL")

print("------------------------------")
print("Correct:", correct, "/", len(unseen_cases))
print(f"Unseen Accuracy: {correct / len(unseen_cases) * 100:.2f}%")