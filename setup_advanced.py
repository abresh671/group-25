#!/usr/bin/env python3
"""
Advanced setup script for phishing detection system
Generates comprehensive dataset, trains ensemble model, and runs tests
"""

import os
import sys
import subprocess
import time
from datetime import datetime

def print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════╗
║           Advanced Phishing Detection System Setup          ║
║                        Version 2.0                          ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def run_command(cmd, description, critical=True):
    print(f"\\n{'='*60}")
    print(f"🔄 {description}")
    print(f"Command: {cmd}")
    print(f"{'='*60}")
    
    start_time = time.time()
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    end_time = time.time()
    
    if result.stdout:
        print("STDOUT:")
        print(result.stdout)
    
    if result.stderr:
        print("STDERR:")
        print(result.stderr)
    
    duration = end_time - start_time
    
    if result.returncode != 0:
        print(f"❌ Failed: {description} (took {duration:.1f}s)")
        if critical:
            print("🛑 Critical step failed. Exiting.")
            sys.exit(1)
        return False
    else:
        print(f"✅ Success: {description} (took {duration:.1f}s)")
        return True

def check_python_version():
    """Check if Python version is compatible"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ Python 3.8+ required")
        sys.exit(1)
    print(f"✅ Python {version.major}.{version.minor}.{version.micro}")

def install_requirements():
    """Install required packages"""
    if os.path.exists("requirements.txt"):
        return run_command("pip install -r requirements.txt", "Install requirements", critical=True)
    else:
        print("⚠️  requirements.txt not found, skipping package installation")
        return True

def generate_dataset():
    """Generate comprehensive dataset"""
    return run_command("python dataset_generator.py", "Generate comprehensive dataset")

def train_model():
    """Train the advanced model"""
    return run_command("python train_advanced.py", "Train advanced ensemble model")

def test_prediction():
    """Test prediction functionality"""
    test_urls = [
        "https://www.google.com",
        "https://paypal-security-alert.tk",
        "https://amazon-account-suspended.ml"
    ]
    
    print("\\n🧪 Testing predictions...")
    for url in test_urls:
        print(f"Testing: {url}")
        result = subprocess.run(
            f'python predict_advanced.py "{url}"',
            shell=True, capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"✅ {result.stdout.strip()}")
        else:
            print(f"❌ Failed: {result.stderr.strip()}")

def test_web_app():
    """Test web application startup"""
    print("\\n🌐 Testing web application...")
    # Just check if the app can import without errors
    result = subprocess.run(
        "python -c \"from app_advanced import app; print('Web app imports successfully')\"",
        shell=True, capture_output=True, text=True
    )
    if result.returncode == 0:
        print("✅ Web application ready")
        return True
    else:
        print(f"❌ Web app test failed: {result.stderr}")
        return False

def create_sample_files():
    """Create sample URL files for testing"""
    sample_urls = """https://www.google.com
https://www.facebook.com
https://paypal-security-alert.tk
https://amazon-account-suspended.ml
https://microsoft-login-verify.ga
https://www.github.com
https://apple-id-locked.cf
https://www.stackoverflow.com"""
    
    with open("sample_urls.txt", "w") as f:
        f.write(sample_urls)
    
    print("✅ Created sample_urls.txt for testing")

def main():
    print_banner()
    print(f"Setup started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Step 1: Check Python version
    print("\\n🐍 Checking Python version...")
    check_python_version()
    
    # Step 2: Install requirements
    print("\\n📦 Installing requirements...")
    if not install_requirements():
        print("⚠️  Package installation failed, continuing anyway...")
    
    # Step 3: Generate dataset
    print("\\n📊 Generating dataset...")
    if not generate_dataset():
        print("🛑 Dataset generation failed")
        sys.exit(1)
    
    # Step 4: Train model
    print("\\n🤖 Training model...")
    if not train_model():
        print("🛑 Model training failed")
        sys.exit(1)
    
    # Step 5: Test predictions
    print("\\n🧪 Testing predictions...")
    test_prediction()
    
    # Step 6: Test web app
    print("\\n🌐 Testing web application...")
    test_web_app()
    
    # Step 7: Create sample files
    print("\\n📄 Creating sample files...")
    create_sample_files()
    
    # Final summary
    print("\\n" + "="*60)
    print("🎉 SETUP COMPLETE!")
    print("="*60)
    print("\\nYou can now use the system:")
    print("\\n1. 🖥️  CLI Interface:")
    print("   python cli_advanced.py --interactive")
    print("   python cli_advanced.py https://suspicious-url.com")
    print("   python cli_advanced.py --file sample_urls.txt")
    
    print("\\n2. 🌐 Web Interface:")
    print("   python app_advanced.py")
    print("   Then open: http://127.0.0.1:5000")
    
    print("\\n3. 🔍 Direct Prediction:")
    print("   python predict_advanced.py https://example.com")
    
    print("\\n4. 📊 Explanation:")
    print("   python explain.py")
    
    print("\\n5. 📈 Model Info:")
    print("   python cli_advanced.py --info")
    
    print(f"\\nSetup completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\\n🛡️  Your advanced phishing detection system is ready!")

if __name__ == "__main__":
    main()