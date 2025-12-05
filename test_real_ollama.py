#!/usr/bin/env python3
"""
Test real Ollama integration with format parameter.
Verifies that the fix actually works with a live Ollama instance.
"""
import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from packages.llm_analysis.llm.providers import OllamaProvider
from packages.llm_analysis.llm.config import ModelConfig

def test_url_parsing():
    """Test that URLs are correctly parsed (the bug we're fixing)."""
    print("\n" + "="*70)
    print("TEST 1: URL Parsing (Bug Fix Verification)")
    print("="*70)

    config = ModelConfig(
        provider="ollama",
        model_name="mistral:latest",  # 7B model for reliable testing
        api_base="http://localhost:11434",
        temperature=0.0,
        max_tokens=512,
        timeout=60,
    )

    provider = OllamaProvider(config)

    schema = {
        "url": "string",
        "status": "string",
        "description": "string"
    }

    prompt = "Generate a JSON object with a URL field containing 'http://example.com/api/v1/users', a status field with 'active', and a description field with 'API endpoint'."

    try:
        result, raw = provider.generate_structured(prompt, schema)

        print(f"\n✓ Success! Generated structured JSON:")
        print(f"  Result: {json.dumps(result, indent=2)}")

        # Check if URL is intact
        if "url" in result:
            url = result["url"]
            print(f"\n  URL field value: {url}")

            if "http" in url and "//" in url:
                print(f"  ✓ URL is intact (not broken by comment removal)")
                return True
            else:
                print(f"  ✗ URL is malformed (bug still exists)")
                return False
        else:
            print(f"  ⚠ No URL field in result")
            return False

    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False

def test_format_parameter():
    """Test that format parameter is being used."""
    print("\n" + "="*70)
    print("TEST 2: Format Parameter Usage")
    print("="*70)

    config = ModelConfig(
        provider="ollama",
        model_name="mistral:latest",  # 7B model for reliable testing
        api_base="http://localhost:11434",
        temperature=0.0,
        max_tokens=256,
        timeout=60,
    )

    provider = OllamaProvider(config)

    schema = {
        "result": "boolean",
        "confidence": "number"
    }

    prompt = "Is Python a programming language? Respond with result (true/false) and confidence (0-100)."

    try:
        result, raw = provider.generate_structured(prompt, schema)

        print(f"\n✓ Success! Generated structured JSON:")
        print(f"  Result: {json.dumps(result, indent=2)}")
        print(f"  Raw response length: {len(raw)} chars")

        # Try to parse raw response directly (should work if format parameter worked)
        try:
            direct_parse = json.loads(raw.strip())
            print(f"\n  ✓ Raw response is valid JSON (format parameter likely worked)")
            return True
        except json.JSONDecodeError:
            print(f"\n  ⚠ Raw response needed cleanup (format parameter may not have worked)")
            print(f"  Raw (first 200 chars): {raw[:200]}")
            return False

    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_complex_nested_json():
    """Test with more complex nested structure."""
    print("\n" + "="*70)
    print("TEST 3: Complex Nested JSON")
    print("="*70)

    config = ModelConfig(
        provider="ollama",
        model_name="mistral:latest",  # 7B model for reliable testing
        api_base="http://localhost:11434",
        temperature=0.0,
        max_tokens=512,
        timeout=60,
    )

    provider = OllamaProvider(config)

    schema = {
        "vulnerability": {
            "name": "string",
            "severity": "string",
            "cwe_ids": ["string"],
            "description": "string"
        }
    }

    prompt = "Generate a vulnerability object with name 'SQL Injection', severity 'High', cwe_ids ['CWE-89'], and description 'Improper input validation'."

    try:
        result, raw = provider.generate_structured(prompt, schema)

        print(f"\n✓ Success! Generated structured JSON:")
        print(f"  Result: {json.dumps(result, indent=2)}")

        # Verify structure
        if "vulnerability" in result:
            vuln = result["vulnerability"]
            if all(k in vuln for k in ["name", "severity", "cwe_ids", "description"]):
                print(f"\n  ✓ All required fields present")
                return True
            else:
                print(f"\n  ⚠ Missing required fields")
                return False
        else:
            print(f"\n  ⚠ No vulnerability field in result")
            return False

    except Exception as e:
        print(f"\n✗ Error: {e}")
        return False

if __name__ == "__main__":
    print("\n" + "="*70)
    print("REAL OLLAMA INTEGRATION TEST")
    print("Testing format parameter fix with live Ollama instance")
    print("="*70)

    results = []

    # Run tests
    results.append(("URL Parsing", test_url_parsing()))
    results.append(("Format Parameter", test_format_parameter()))
    results.append(("Complex Nested JSON", test_complex_nested_json()))

    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)

    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {name}")

    total = len(results)
    passed = sum(1 for _, p in results if p)

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n✓ All tests passed! Fix is working with real Ollama.")
        sys.exit(0)
    else:
        print(f"\n✗ {total - passed} test(s) failed. Fix may need adjustment.")
        sys.exit(1)
