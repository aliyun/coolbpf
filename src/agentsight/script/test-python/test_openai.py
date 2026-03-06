#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 eunomia-bpf org.

"""
Test program to generate OpenAI API traffic for sslsniff monitoring.
"""
import os
from pathlib import Path
from dotenv import load_dotenv
from openai import OpenAI

def main():
    # Load .env file from the script's directory
    script_dir = Path(__file__).parent
    env_file = script_dir / ".env"
    load_dotenv(env_file)

    # Initialize OpenAI client
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Error: OPENAI_API_KEY environment variable not set")
        print("Please set it in test/.env file")
        return 1

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    client = OpenAI(api_key=api_key)

    print(f"Sending request to OpenAI API (model: {model})...")
    print("This traffic should be captured by sslsniff\n")

    try:
        # Make a simple API call
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "user", "content": "Say hello in exactly 5 words"}
            ],
            max_completion_tokens=500
        )

        print("Response received:")
        print(response.choices[0].message.content)
        print("\nRequest completed successfully!")
        return 0

    except Exception as e:
        print(f"Error making API request: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
