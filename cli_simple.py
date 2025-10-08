#!/usr/bin/env python3
"""
Simple CLI for Hooked phishing detection system
"""

import sys
from predict_advanced import predict, get_model_info

def main():
    print("=" * 50)
    print("    HOOKED - Phishing Detection CLI")
    print("=" * 50)
    
    if len(sys.argv) < 2:
        print("Usage: python cli_simple.py <URL>")
        print("Example: python cli_simple.py https://google.com")
        return
    
    url = sys.argv[1]
    print(f"Analyzing: {url}")
    print("-" * 50)
    
    try:
        pred, proba = predict(url, use_network=False)
        
        if pred is not None:
            status = "HOOKED (Phishing)" if pred == 1 else "SAFE (Legitimate)"
            confidence = f"{proba * 100:.1f}%" if proba else "Unknown"
            
            print(f"Result: {status}")
            print(f"Confidence: {confidence}")
            
            if pred == 1:
                print("WARNING: This URL appears to be a phishing attempt!")
            else:
                print("This URL appears to be legitimate.")
        else:
            print("ERROR: Could not analyze URL")
    
    except Exception as e:
        print(f"ERROR: {e}")
    
    print("-" * 50)

if __name__ == "__main__":
    main()