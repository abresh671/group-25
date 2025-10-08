#!/usr/bin/env python3
"""
Setup script for Hooked phishing detection system
"""

import os
import sys
import subprocess

def run_command(cmd, description):
    """Run a command and handle errors"""
    print(f"[INFO] {description}...")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print(f"[OK] {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] {description} failed: {e}")
        return False

def main():
    print("=" * 60)
    print("    HOOKED - Phishing Detection System Setup")
    print("=" * 60)
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("[ERROR] Python 3.8 or higher required")
        return False
    
    print(f"[OK] Python {sys.version.split()[0]} detected")
    
    # Install requirements
    if not run_command("pip install -r requirements.txt", "Installing dependencies"):
        return False
    
    # Create model directory
    if not os.path.exists("model"):
        os.makedirs("model")
        print("[OK] Model directory created")
    
    # Train model if not exists
    if not os.path.exists("model/phish_advanced.joblib"):
        print("[INFO] Training model (this may take a few minutes)...")
        if not run_command("python train_advanced.py", "Training model"):
            return False
    else:
        print("[OK] Model already exists")
    
    # Create frontend dist if not exists
    if not os.path.exists("frontend/dist"):
        os.makedirs("frontend/dist", exist_ok=True)
        print("[OK] Frontend directory created")
    
    print("\n" + "=" * 60)
    print("    SETUP COMPLETE!")
    print("=" * 60)
    print("To start the system:")
    print("  Web Interface: python app_frontend.py")
    print("  Simple CLI:    python cli_simple.py <URL>")
    print("  Advanced CLI:  python cli_advanced.py --help")
    print("=" * 60)
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)