# Hooked - Advanced Phishing Detection System

Don't get caught by phishing! Hooked is a comprehensive ML system that detects phishing URLs before they can hook you.

## Features
- 🎣 **Smart Detection**: 56+ features analyze URL patterns to spot phishing hooks
- 🧠 **AI-Powered**: Ensemble ML models with 94.4% accuracy
- ⚡ **Real-time**: Instant URL analysis
- 🌐 **Multiple Interfaces**: Web UI, CLI, and REST API
- 📊 **Explainable**: SHAP-based feature importance

## Quick Start

1. **One-command setup:**
   ```bash
   python setup.py
   ```

2. **Start using Hooked:**
   ```bash
   # Web interface (recommended)
   python app_frontend.py
   # Then open: http://127.0.0.1:5000
   
   # Simple CLI
   python cli_simple.py https://suspicious-site.com
   
   # Advanced CLI with options
   python cli_advanced.py --interactive
   ```

## System Architecture

### Core Components
- `featureExtractor.py` - Feature extraction engine (56+ features)
- `train_advanced.py` - ML model training (XGBoost, LightGBM, Random Forest)
- `predict_advanced.py` - Prediction engine with ensemble voting
- `explain.py` - SHAP-based explainable AI

### Interfaces
- `app_frontend.py` - Modern web interface
- `cli_simple.py` - Easy-to-use CLI
- `cli_advanced.py` - Full-featured CLI with batch processing

### Setup & Utilities
- `setup.py` - One-command system setup
- `dataset_generator.py` - Training data preparation

## Technical Details

### Machine Learning
- **Models**: Ensemble of XGBoost, LightGBM, Random Forest
- **Accuracy**: 94.4% on test data
- **Features**: 56+ URL analysis features
- **Training**: Balanced dataset with phishing/legitimate URLs

### API Endpoints
- `POST /api/check` - Single URL analysis
- `POST /api/batch` - Multiple URL analysis
- `POST /api/explain` - Feature importance explanation
- `GET /api/model/info` - Model information
- `GET /api/health` - System health check

### Deployment
- **Frontend**: Responsive web interface
- **Backend**: Flask REST API
- **CLI**: Command-line tools for automation
- **Cross-platform**: Windows, macOS, Linux support