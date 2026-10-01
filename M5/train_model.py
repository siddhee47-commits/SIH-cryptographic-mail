import csv
import math
import pickle
from collections import Counter


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


def load_data(filename):
    data = []

    with open(filename, "r", newline="") as file:
        reader = csv.DictReader(file)

        for row in reader:
            features = [int(row[f]) for f in FEATURES]
            label = row["risk_label"]

            data.append((features, label))

    return data


def entropy(labels):
    counts = Counter(labels)
    total = len(labels)

    result = 0

    for count in counts.values():
        probability = count / total
        result -= probability * math.log2(probability)

    return result


def information_gain(data, feature_index):
    parent_labels = [label for _, label in data]

    parent_entropy = entropy(parent_labels)

    left = []
    right = []

    for features, label in data:
        if features[feature_index] == 0:
            left.append((features, label))
        else:
            right.append((features, label))

    if not left or not right:
        return 0

    left_entropy = entropy([label for _, label in left])
    right_entropy = entropy([label for _, label in right])

    weighted_entropy = (
        len(left) / len(data) * left_entropy
        + len(right) / len(data) * right_entropy
    )

    return parent_entropy - weighted_entropy


def majority_label(data):
    labels = [label for _, label in data]
    return Counter(labels).most_common(1)[0][0]


def build_tree(data, available_features=None):

    labels = [label for _, label in data]

    # If all samples have same label
    if len(set(labels)) == 1:
        return {
            "type": "leaf",
            "label": labels[0]
        }

    # If no features remain
    if not available_features:
        return {
            "type": "leaf",
            "label": majority_label(data)
        }

    # Find best feature
    best_feature = None
    best_gain = -1

    for feature_index in available_features:

        gain = information_gain(data, feature_index)

        if gain > best_gain:
            best_gain = gain
            best_feature = feature_index

    # No useful split
    if best_feature is None or best_gain <= 0:
        return {
            "type": "leaf",
            "label": majority_label(data)
        }

    left = []
    right = []

    for features, label in data:

        if features[best_feature] == 0:
            left.append((features, label))
        else:
            right.append((features, label))

    remaining_features = [
        f for f in available_features
        if f != best_feature
    ]

    return {
        "type": "node",
        "feature": best_feature,
        "feature_name": FEATURES[best_feature],
        "left": build_tree(left, remaining_features),
        "right": build_tree(right, remaining_features)
    }


def predict(tree, features):

    if tree["type"] == "leaf":
        return tree["label"]

    feature_index = tree["feature"]

    if features[feature_index] == 0:
        return predict(tree["left"], features)

    return predict(tree["right"], features)


# -----------------------------
# TRAIN MODEL
# -----------------------------

data = load_data("training_data.csv")

print(f"Training samples: {len(data)}")

tree = build_tree(
    data,
    list(range(len(FEATURES)))
)

# Save model
with open("ml_model.pkl", "wb") as file:
    pickle.dump(tree, file)

print("Model trained successfully.")
print("Model saved as ml_model.pkl")


# -----------------------------
# TEST MODEL
# -----------------------------

correct = 0

for features, actual in data:

    predicted = predict(tree, features)

    if predicted == actual:
        correct += 1

accuracy = correct / len(data) * 100

print(f"Training accuracy: {accuracy:.2f}%")