from ml_predictor import predict_risk


def calculate_risk(features):
    """
    Calculate risk using rule-based scoring and ML prediction.
    """

    score = 0

    # Severity-based scoring
    score += features.get("critical_findings", 0) * 40
    score += features.get("high_findings", 0) * 25
    score += features.get("medium_findings", 0) * 10

    # Specific security conditions
    score += features.get("weak_tls_version", 0) * 20
    score += features.get("weak_cipher", 0) * 20
    score += features.get("no_forward_secrecy", 0) * 10
    score += features.get("weak_public_key", 0) * 20
    score += features.get("expired_certificate", 0) * 25
    score += features.get("invalid_certificate_chain", 0) * 25
    score += features.get("weak_signature_algorithm", 0) * 20

    # Missing STARTTLS
    score += features.get("starttls_missing", 0) * 25

    # Maximum score
    score = min(score, 100)

    # Rule-based risk
    if score >= 70:
        rule_risk = "CRITICAL"
    elif score >= 40:
        rule_risk = "HIGH"
    elif score >= 20:
        rule_risk = "MEDIUM"
    else:
        rule_risk = "LOW"

    # ML prediction
    ml_risk = predict_risk(features)

    # Convert risk levels to numeric values
    risk_values = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    # Select the higher risk level
    if risk_values[ml_risk] > risk_values[rule_risk]:
        final_risk = ml_risk
    else:
        final_risk = rule_risk

    return {
        "risk_score": score,
        "risk_level": rule_risk,
        "ml_risk": ml_risk,
        "final_risk": final_risk
    }