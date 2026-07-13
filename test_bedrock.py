from bedrock_client import generate_security_report

response = generate_security_report("Say hello in one sentence.")

print("\n===== MODEL RESPONSE =====\n")
print(response)