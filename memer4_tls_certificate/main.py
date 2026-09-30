import json
import os
from member4_engine import analyze


def main():
    m3_file = os.path.join(
        "..",
        "M3",
        "output",
        "member3_results.json"
    )

    if not os.path.exists(m3_file):
        print("M3 output not found:")
        print(m3_file)
        return

    with open(m3_file, "r", encoding="utf-8") as f:
        m3_data = json.load(f)

    result = analyze(m3_data)

    output_file = "member4_output.json"

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4)

    print("================================")
    print("M4 TLS & Certificate Analysis")
    print("================================")
    print("Streams analyzed:", result["streams_analyzed"])
    print("Output:", output_file)
    print("M4 analysis completed successfully.")


if __name__ == "__main__":
    main()
