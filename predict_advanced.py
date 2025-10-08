import os
import pandas as pd
from joblib import load
from scipy.sparse import hstack, csr_matrix
import numpy as np
import socket
import requests
from urllib.parse import urlparse
import re

from featureExtractor import extract_all_features
from database_checker import check_phishing_databases, check_dns_reputation

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

def check_domain_exists(domain: str) -> bool:
    """Check if domain exists via DNS lookup"""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return True  # Assume exists if other error

def check_url_accessible(url: str) -> bool:
    """Check if URL is accessible"""
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code < 400
    except requests.exceptions.RequestException:
        return False
    except Exception:
        return True  # Assume accessible if other error

def predict(url: str, use_network: bool = False, include_advice: bool = False):
    try:
        model, tfidf, scaler, numeric_cols = load_artifacts()
        X = url_to_features(url, tfidf, scaler, numeric_cols, use_network=use_network)
        
        # Get probability if available
        proba = None
        if hasattr(model, "predict_proba"):
            proba_scores = model.predict_proba(X)[0]
            proba = float(proba_scores[1])  # Probability of phishing
        
        # Enhanced suspicious pattern detection with internet verification
        analysis_reasons = []
        try:
            # Clean URL and parse
            clean_url = url.replace('&amp;', '&')  # Fix HTML entities
            parsed = urlparse(clean_url if clean_url.startswith(('http://', 'https://')) else 'http://' + clean_url)
            domain = parsed.netloc.lower()
            if domain.startswith('www.'):
                domain = domain[4:]  # Remove www. for checking
            full_url = clean_url.lower()
            
            # Whitelist of known legitimate domains
            legitimate_domains = {
                'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'wikipedia.org',
                'twitter.com', 'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com',
                'microsoft.com', 'apple.com', 'netflix.com', 'reddit.com', 'ebay.com',
                'paypal.com', 'dropbox.com', 'adobe.com', 'salesforce.com', 'zoom.us',
                'kaggle.com', 'medium.com', 'quora.com', 'pinterest.com', 'tumblr.com',
                'twitch.tv', 'discord.com', 'slack.com', 'notion.so', 'figma.com',
                'canva.com', 'trello.com', 'atlassian.com', 'bitbucket.org', 'gitlab.com'
            }
            
            # Enhanced database verification - check first
            phishing_db_result = check_phishing_databases(domain)
            dns_reputation = check_dns_reputation(domain) if use_network else {'suspicious': False, 'details': []}
            
            # Database results take highest priority
            if phishing_db_result['is_phishing']:
                analysis_reasons.extend([f"[DATABASE] {source}" for source in phishing_db_result['sources']])
                analysis_reasons.append("[DANGER] Domain flagged by security databases")
                if include_advice:
                    return 1, 0.95, analysis_reasons
                return 1, 0.95
            
            if phishing_db_result['is_safe']:
                analysis_reasons.extend([f"[DATABASE] {source}" for source in phishing_db_result['sources']])
                analysis_reasons.append("[SAFE] Domain verified as legitimate")
                if include_advice:
                    return 0, 0.05, analysis_reasons
                return 0, 0.05
            
            # Check if domain is in legacy whitelist
            is_legitimate = any(domain == legit or domain.endswith('.' + legit) for legit in legitimate_domains)
            
            if is_legitimate:
                analysis_reasons.append(f"[SAFE] Trusted domain: {domain} is a well-known legitimate website")
                analysis_reasons.append("[SAFE] Domain is in our whitelist of verified safe sites")
                if include_advice:
                    return 0, min(0.1, proba) if proba else 0.05, analysis_reasons
                return 0, min(0.1, proba) if proba else 0.05
            
            # Internet verification for unknown domains
            domain_exists = check_domain_exists(parsed.netloc) if use_network else True
            
            # Check for obvious phishing patterns (only for non-legitimate domains)
            suspicious_flags = []
            
            if len(parsed.netloc) > 30:
                suspicious_flags.append("[WARNING] Very long domain name (suspicious)")
            if parsed.netloc.count('-') > 3:
                suspicious_flags.append("[WARNING] Too many hyphens in domain (common in phishing)")
            if parsed.netloc.count('.') > 4:
                suspicious_flags.append("[WARNING] Too many subdomains (suspicious structure)")
            if bool(re.search(r'[a-z]{15,}', parsed.netloc)):
                suspicious_flags.append("[WARNING] Long random character strings in domain")
            if bool(re.search(r'[qwxz]{4,}', parsed.netloc)):
                suspicious_flags.append("[WARNING] Uncommon letter combinations (likely random)")
            if parsed.netloc.endswith(('.tk', '.ml', '.ga', '.cf')):
                suspicious_flags.append("[WARNING] Suspicious top-level domain (often used by scammers)")
            if '/spaces/' in full_url and len(parsed.netloc) > 20:
                suspicious_flags.append("[WARNING] Suspicious URL path pattern")
            if not parsed.netloc or parsed.netloc == 'localhost':
                suspicious_flags.append("[WARNING] Invalid or local domain")
            if any(f'{brand}-' in parsed.netloc or f'{brand}.' in parsed.netloc 
                   for brand in ['paypal', 'amazon', 'google', 'microsoft', 'apple'] 
                   if not parsed.netloc.endswith(f'{brand}.com')):
                suspicious_flags.append("[WARNING] Possible brand impersonation attempt")
            if not domain_exists:
                suspicious_flags.append("[WARNING] Domain does not exist or cannot be resolved")
            
            if suspicious_flags:
                analysis_reasons.extend(suspicious_flags)
                analysis_reasons.append("[DANGER] Multiple suspicious indicators detected - likely phishing")
                if include_advice:
                    return 1, max(0.85, proba) if proba else 0.90, analysis_reasons
                return 1, max(0.85, proba) if proba else 0.90
            else:
                analysis_reasons.append("[SAFE] Domain structure appears normal")
                analysis_reasons.append("[SAFE] No obvious suspicious patterns detected")
                
        except Exception as e:
            print(f"Pattern detection error: {e}")
            analysis_reasons.append(f"[ERROR] Analysis error: {e}")
        
        # Use model prediction with balanced threshold
        pred = int(model.predict(X)[0])
        
        # Check if analysis shows it's safe but model disagrees
        has_suspicious_flags = any("WARNING" in reason or "DANGER" in reason for reason in analysis_reasons)
        
        # Only trust high-confidence phishing predictions with suspicious patterns
        if pred == 1 and not has_suspicious_flags:
            # Model says phishing but no suspicious patterns found
            if proba and proba < 0.9:  # Unless very high confidence
                pred = 0  # Override to safe
                analysis_reasons.append(f"[AI] Model flagged as phishing ({proba:.1%}) but no suspicious patterns found")
                analysis_reasons.append("[OVERRIDE] Classified as safe due to lack of suspicious indicators")
        
        # Add final analysis
        if pred == 1:
            if not any("AI" in reason for reason in analysis_reasons):
                analysis_reasons.append(f"[AI] Model detected phishing patterns ({proba:.1%} confidence)")
            analysis_reasons.append("[ADVICE] Recommendation: Do not visit this site or enter personal information")
        else:
            if proba and proba > 0.5:
                analysis_reasons.append(f"[AI] Model shows elevated risk ({proba:.1%}) but classified as safe")
            elif proba and proba < 0.3:
                analysis_reasons.append(f"[AI] Model shows low risk ({proba:.1%} phishing probability)")
            analysis_reasons.append("[SAFE] URL appears safe to visit")
        
        if include_advice:
            return pred, proba, analysis_reasons
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
                
                # Apply enhanced suspicious pattern check for batch
                from urllib.parse import urlparse
                import re
                try:
                    parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
                    domain = parsed.netloc.lower()
                    full_url = url.lower()
                    
                    suspicious_patterns = [
                        len(domain) > 25,
                        domain.count('-') > 2,
                        domain.count('.') > 3,
                        bool(re.search(r'[a-z]{10,}', domain)),
                        bool(re.search(r'[qwxz]{3,}', domain)),
                        domain.endswith(('.tk', '.ml', '.ga', '.cf', '.co')),
                        '/spaces/' in full_url and len(domain) > 15,
                        not domain or domain == 'localhost'
                    ]
                    
                    if any(suspicious_patterns):
                        pred = 1
                        proba = max(0.85, proba) if proba else 0.90
                    elif proba and proba > 0.3:
                        pred = 1
                except:
                    pass
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