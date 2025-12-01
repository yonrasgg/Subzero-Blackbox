#!/usr/bin/env python3
"""
scripts/test_gemini.py

Script to test Google Gemini API connection and list available models.
"""

import os
import sys
from pathlib import Path
import yaml

# Try to import the library
try:
    import google.generativeai as genai
except ImportError:
    print("Error: google-generativeai library not installed.")
    print("pip install google-generativeai")
    sys.exit(1)

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config" / "config.yaml"
SECRETS_PATH = BASE_DIR / "config" / "secrets.yaml"

def get_api_key():
    # 1. Try secrets.yaml
    if SECRETS_PATH.is_file():
        try:
            data = yaml.safe_load(SECRETS_PATH.read_text())
            key = data.get("apis", {}).get("google_api_key")
            if key:
                return key
        except Exception as e:
            print(f"Error reading secrets.yaml: {e}")

    # 2. Try environment variable
    return os.getenv("GOOGLE_AI_API_KEY")

def main():
    api_key = get_api_key()
    if not api_key:
        print("[-] No API Key found in config/secrets.yaml or GOOGLE_AI_API_KEY env var.")
        return

    print(f"[*] Found API Key: {api_key[:5]}...{api_key[-4:]}")
    
    # Configure the library
    genai.configure(api_key=api_key)

    print("\n[*] Listing available models...")
    try:
        found_flash = False
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                print(f"    - {m.name}")
                if "gemini-1.5-flash" in m.name:
                    found_flash = True
        
        if not found_flash:
            print("\n[!] Warning: 'gemini-1.5-flash' not found in the list.")
    except Exception as e:
        print(f"[-] Error listing models: {e}")
        return

    # Test generation with a few candidates
    candidates = [
        "gemini-2.0-flash",
        "gemini-2.5-flash",
        "gemini-1.5-flash",
    ]

    print("\n[*] Testing generation with candidates...")
    for model_name in candidates:
        print(f"    Testing '{model_name}'...", end=" ", flush=True)
        try:
            model = genai.GenerativeModel(model_name)
            response = model.generate_content("Hello, are you working?")
            if response.text:
                print(f"SUCCESS! Response: {response.text.strip()[:30]}...")
                # If successful, we can stop or keep testing others
            else:
                print("Empty response.")
        except Exception as e:
            print(f"FAILED. ({str(e)})")

if __name__ == "__main__":
    main()
