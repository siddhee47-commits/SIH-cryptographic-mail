from risk_engine import calculate_risk
from evaluate_unseen import unseen_cases  # ye import nahi chahiye to neeche wali list use karo

print("================================")
print("M5 Final Risk (Rule + ML) - Unseen Cases")
print("================================")

correct = 0
for case in unseen_cases:
    result = calculate_risk(case["features"])
    passed = result["final_risk"] == case["expected"]
    correct += passed

    print("------------------------------")
    print("Test:", case["name"])
    print("Score:", result["risk_score"])
    print("Rule:", result["risk_level"], "| ML:", result["ml_risk"])
    print("Expected:", case["expected"], "| Final:", result["final_risk"])
    print("Result:", "PASS" if passed else "FAIL")

print("------------------------------")
print(f"Final Accuracy: {correct}/{len(unseen_cases)}")