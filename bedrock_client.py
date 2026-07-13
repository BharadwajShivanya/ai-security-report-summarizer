import json

import boto3

from config import (
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    AWS_REGION,
    MODEL_ID,
)

# Create Bedrock Runtime client
client = boto3.client(
    service_name="bedrock-runtime",
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
)


def generate_security_report(prompt: str) -> str:
    """
    Sends a prompt to Amazon Bedrock and returns only the generated text.
    """

    request_body = {
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "text": prompt
                    }
                ]
            }
        ]
    }

    try:
        response = client.invoke_model(
            modelId=MODEL_ID,
            body=json.dumps(request_body),
            contentType="application/json",
            accept="application/json",
        )

        response_body = json.loads(response["body"].read())

        generated_text = (
            response_body["output"]["message"]["content"][0]["text"]
        )

        return generated_text

    except Exception as e:
        raise RuntimeError(f"Bedrock invocation failed: {e}")