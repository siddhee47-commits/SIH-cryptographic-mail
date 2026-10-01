import pickle

FEATURES = [
    "critical_findings",
    "high_findings",
    "medium_findings",
    "weak_tls_version",
    "weak_cipher",
    "no_forward_secrecy",
    "weak_public_key",
    "expired_certificate",
    "invalid_certificate_chain",
    "weak_signature_algorithm",
    "starttls_missing"
]


def load_model():
    with open("ml_model.pkl", "rb") as file:
        return pickle.load(file)


def predict(tree, features):

    if tree["type"] == "leaf":
        return tree["label"]

    feature_index = tree["feature"]

    if features[feature_index] == 0:
        return predict(tree["left"], features)

    return predict(tree["right"], features)


def predict_risk(features):

    model = load_model()

    feature_values = [
        int(features.get(feature, 0))
        for feature in FEATURES
    ]

    return predict(model, feature_values)