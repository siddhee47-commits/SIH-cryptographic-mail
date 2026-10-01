import json
import os

from feature_extractor import extract_features
from risk_engine import calculate_risk


def main():

    base_dir = os.path.dirname(os.path.abspath(__file__))

    m4_file = os.path.join(
        base_dir,
        "..",
        "memer4_tls_certificate",
        "member4_output.json"
    )

    output_dir = os.path.join(base_dir, "output")
    output_file = os.path.join(
        output_dir,
        "member5_results.json"
    )

    if not os.path.exists(m4_file):
        print("M4 output not found:")
        print(m4_file)
        return

    os.makedirs(output_dir, exist_ok=True)

    with open(m4_file, "r", encoding="utf-8") as f:
        m4_data = json.load(f)

    results = []

    for stream in m4_data.get("results", []):

        features = extract_features(stream)

        risk = calculate_risk(features)

        results.append({
            "stream_id": stream.get("stream_id"),
            "protocol": stream.get("protocol"),
            "features": features,
            "risk": risk,
            "findings": stream.get("findings", [])
        })

    output = {
        "module": "M5 - AI/ML and Risk Engine",
        "streams_analyzed": len(results),
        "results": results
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)

    print("================================")
    print("M5 AI/ML & Risk Engine")
    print("================================")
    print("Streams analyzed:", len(results))
    print("Output:", output_file)
    print("M5 analysis completed successfully.")


if __name__ == "__main__":
    main()