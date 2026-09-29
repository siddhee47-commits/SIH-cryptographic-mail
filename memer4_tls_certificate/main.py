import json
import sys

from member4_engine import Member4Engine


def main():
    # Default input file
    input_file = "sample_input.json"

    # Allow custom input file from command line
    if len(sys.argv) > 1:
        input_file = sys.argv[1]

    # Read input JSON
    try:
        with open(input_file, "r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return
    except json.JSONDecodeError:
        print(f"Error: '{input_file}' is not valid JSON.")
        return

    # Create Member 4 engine
    engine = Member4Engine()

    # Analyze TLS and certificate information
    result = engine.analyze(data)

    # Save output
    output_file = "member4_output.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    # Display result
    print("\n===== MEMBER 4: TLS & CERTIFICATE ANALYSIS =====\n")
    print(json.dumps(result, indent=4))

    print(f"\nOutput saved to: {output_file}")


if __name__ == "__main__":
    main()