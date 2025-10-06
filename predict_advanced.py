import os
import pandas as pd
from joblib import load
from scipy.sparse import hstack, csr_matrix
import numpy as np

from featureExtractor import extract_all_features

MODEL_DIR = "model"
MODEL_NAME = "phish_advanced.joblib"

def load_artifacts():
    path = os.path.join(MODEL_DIR, MODEL_NAME)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Model not found at {path}. Train with train_advanced.py first.")
    
    artifacts = load(path)
    return (
        artifacts['model'], 
        artifacts['tfidf'], 
        artifacts['scaler'], 
        artifacts['numeric_columns']
    )

def url_to_features(url: str, tfidf, scaler, numeric_columns, use_network: bool = False):
    try:
        # Extract numerical features
        num_features = extract_all_features(url, use_network=use_network)
        df = pd.DataFrame([num_features])
        
        # Ensure all expected columns are present
        for col in numeric_columns:
            if col not in df.columns:
                df[col] = -1
        
        # Select and order columns correctly
        Xnum = df[numeric_columns].fillna(-1).astype(float)
        Xnum_scaled = scaler.transform(Xnum)
        
        # Extract text features
        normalized_url = url if url.startswith(('http://', 'https://')) else 'http://' + url
        Xtext = tfidf.transform([normalized_url])
        
        # Combine features
        Xfull = hstack([csr_matrix(Xnum_scaled), Xtext])
        return Xfull
    
    except Exception as e:
        print(f"Error in feature extraction: {e}")
        raise

def predict(url: str, use_network: bool = False):
    try:
        model, tfidf, scaler, numeric_cols = load_artifacts()
        X = url_to_features(url, tfidf, scaler, numeric_cols, use_network=use_network)
        
        # Get probability if available
        proba = None
        if hasattr(model, "predict_proba"):
            proba_scores = model.predict_proba(X)[0]
            proba = float(proba_scores[1])  # Probability of phishing
        
        # Apply domain whitelist for known safe domains
        safe_domains = {
            'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'wikipedia.org',
            'twitter.com', 'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
            'microsoft.com', 'apple.com', 'netflix.com', 'reddit.com', 'ebay.com',
            'paypal.com', 'dropbox.com', 'adobe.com', 'salesforce.com', 'zoom.us',
            'kaggle.com', 'medium.com', 'quora.com', 'pinterest.com', 'tumblr.com'
        }
        
        from urllib.parse import urlparse
        try:
            domain = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url).netloc.lower()
            # Remove www. prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Check if domain is in safe list
            if any(domain == safe or domain.endswith('.' + safe) for safe in safe_domains):
                return 0, min(0.1, proba) if proba else 0.05  # Force legitimate with low confidence
        except:
            pass
        
        # Adjust threshold - be more conservative
        threshold = 0.7  # Increased from default 0.5
        pred = 1 if proba and proba > threshold else 0
        
        return pred, proba
    
    except Exception as e:
        print(f"Prediction error: {e}")
        return None, None

def predict_batch(urls: list, use_network: bool = False):
    """Predict multiple URLs at once for better efficiency"""
    try:
        model, tfidf, scaler, numeric_cols = load_artifacts()
        
        results = []
        for url in urls:
            try:
                X = url_to_features(url, tfidf, scaler, numeric_cols, use_network=use_network)
                pred = int(model.predict(X)[0])
                proba = None
                if hasattr(model, "predict_proba"):
                    proba = float(model.predict_proba(X)[0][1])
                results.append({'url': url, 'prediction': pred, 'probability': proba})
            except Exception as e:
                results.append({'url': url, 'prediction': None, 'probability': None, 'error': str(e)})
        
        return results
    
    except Exception as e:
        print(f"Batch prediction error: {e}")
        return []

def get_model_info():
    """Get information about the loaded model"""
    try:
        path = os.path.join(MODEL_DIR, MODEL_NAME)
        if not os.path.exists(path):
            return None
        
        artifacts = load(path)
        return {
            'model_type': artifacts.get('model_type', 'unknown'),
            'feature_count': artifacts.get('feature_count', 'unknown'),
            'training_score': artifacts.get('training_score', 'unknown'),
            'numeric_features': len(artifacts['numeric_columns']),
            'text_features': artifacts['tfidf'].get_feature_names_out().shape[0] if hasattr(artifacts['tfidf'], 'get_feature_names_out') else 'unknown'
        }
    except Exception as e:
        return {'error': str(e)}

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("Enter URL: ").strip()
    
    if not url:
        print("No URL provided")
        sys.exit(1)
    
    print(f"Analyzing: {url}")
    pred, proba = predict(url)
    
    if pred is not None:
        label = "PHISHING" if pred == 1 else "LEGITIMATE"
        confidence = f"({proba:.3f})" if proba is not None else ""
        print(f"Result: {label} {confidence}")
        
        # Show model info
        info = get_model_info()
        if info and 'error' not in info:
            print(f"Model: {info['model_type']} with {info['feature_count']} features")
    else:
        print("Prediction failed")