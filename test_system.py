#!/usr/bin/env python3
"""
System test script for Hooked phishing detection
"""

import requests
import time
from predict_advanced import predict

def test_prediction_engine():
    """Test the core prediction functionality"""
    print("Testing prediction engine...")
    
    test_urls = [
        ("https://google.com", 0),  # Should be legitimate
        ("https://paypal-security-update.suspicious.com", 1),  # Should be phishing
        ("https://github.com", 0),  # Should be legitimate
    ]
    
    for url, expected in test_urls:
        try:
            pred, proba = predict(url, use_network=False)
            status = "PASS" if pred == expected else "FAIL"
            print(f"  {status}: {url} -> {pred} (confidence: {proba:.2f})")
        except Exception as e:
            print(f"  ERROR: {url} -> {e}")

def test_api_endpoints():
    """Test the Flask API endpoints"""
    print("\nTesting API endpoints...")
    base_url = "http://127.0.0.1:5000"
    
    # Test health endpoint
    try:
        response = requests.get(f"{base_url}/api/health", timeout=5)
        if response.status_code == 200:
            print("  PASS: Health endpoint working")
        else:
            print(f"  FAIL: Health endpoint returned {response.status_code}")
    except requests.exceptions.RequestException:
        print("  SKIP: API server not running (start with: python app_frontend.py)")
        return
    
    # Test single URL check
    try:
        data = {"url": "https://google.com"}
        response = requests.post(f"{base_url}/api/check", json=data, timeout=10)
        if response.status_code == 200:
            result = response.json()
            print(f"  PASS: URL check -> {result.get('label')} ({result.get('confidence'):.1f}%)")
        else:
            print(f"  FAIL: URL check returned {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"  FAIL: URL check error -> {e}")

def test_model_info():
    """Test model information retrieval"""
    print("\nTesting model information...")
    
    try:
        from predict_advanced import get_model_info
        info = get_model_info()
        if info and 'error' not in info:
            print(f"  PASS: Model type -> {info.get('model_type')}")
            print(f"  PASS: Feature count -> {info.get('feature_count')}")
            print(f"  PASS: Training score -> {info.get('training_score')}")
        else:
            print("  FAIL: Could not retrieve model info")
    except Exception as e:
        print(f"  ERROR: {e}")

def main():
    print("=" * 50)
    print("    HOOKED - System Test Suite")
    print("=" * 50)
    
    start_time = time.time()
    
    test_prediction_engine()
    test_api_endpoints()
    test_model_info()
    
    elapsed = time.time() - start_time
    print(f"\nTests completed in {elapsed:.2f} seconds")
    print("=" * 50)

if __name__ == "__main__":
    main()