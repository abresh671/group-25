# Advanced Phishing Detection System

A comprehensive ML system for phishing URL detection with advanced feature extraction and explainable AI.

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run setup:**
   ```bash
   python setup_advanced.py
   ```

3. **Use the system:**
   ```bash
   # CLI interface
   python cli_advanced.py --interactive
   
   # Web interface  
   python app_advanced.py
   
   # Direct prediction
   python predict_advanced.py https://suspicious-site.com
   ```

## Core Files

- `featureExtractor.py` - Main feature extraction coordinator
- `extractorFunctions.py` - Individual feature extraction components
- `dataset_generator.py` - Comprehensive dataset creation
- `train_advanced.py` - Ensemble model training
- `predict_advanced.py` - Prediction engine
- `app_advanced.py` - Web interface with modern UI
- `cli_advanced.py` - Advanced CLI with batch processing
- `explain.py` - SHAP-based explanations

## Features

- **30+ Advanced Features**: URL structure, domain analysis, heuristics, blacklists
- **Ensemble Learning**: XGBoost, LightGBM, Random Forest
- **Explainable AI**: SHAP feature importance
- **Multiple Interfaces**: CLI, Web UI, REST API
- **Batch Processing**: Analyze multiple URLs efficiently
- **Real-time Analysis**: Fast prediction with comprehensive logging