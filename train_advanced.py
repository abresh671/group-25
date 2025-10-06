import os
import pandas as pd
import numpy as np
from joblib import dump
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import VotingClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from scipy.sparse import hstack, csr_matrix
import warnings
warnings.filterwarnings('ignore')

from featureExtractor import extract_all_features

MODEL_DIR = "model"
MODEL_NAME = "phish_advanced.joblib"

def try_import_models():
    models = []
    
    # Try XGBoost
    try:
        import xgboost as xgb
        xgb_model = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric='logloss',
            tree_method='hist',
            n_jobs=-1,
            random_state=42
        )
        models.append(('xgb', xgb_model))
        print("XGBoost available")
    except ImportError:
        print("[X] XGBoost not available")
    
    # Try LightGBM
    try:
        import lightgbm as lgb
        lgb_model = lgb.LGBMClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            n_jobs=-1,
            random_state=42,
            verbose=-1
        )
        models.append(('lgb', lgb_model))
        print("LightGBM available")
    except ImportError:
        print("[X] LightGBM not available")
    
    # Always available: sklearn models
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.linear_model import LogisticRegression
    
    rf_model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42
    )
    models.append(('rf', rf_model))
    
    gb_model = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42
    )
    models.append(('gb', gb_model))
    
    lr_model = LogisticRegression(
        C=1.0,
        max_iter=1000,
        random_state=42,
        n_jobs=-1
    )
    models.append(('lr', lr_model))
    
    print(f"Total models available: {len(models)}")
    return models

def prepare_features(df: pd.DataFrame, use_network: bool = False):
    print("Extracting features...")
    rows = []
    texts = []
    
    for i, url in enumerate(df['url'].astype(str).tolist()):
        if i % 50 == 0:
            print(f"Processing {i}/{len(df)} URLs...")
        
        try:
            feats = extract_all_features(url, use_network=use_network)
            rows.append(feats)
            texts.append(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        except Exception as e:
            print(f"Error processing URL {url}: {e}")
            # Use default features for failed URLs
            feats = {key: 0 for key in ['url_length', 'host_length', 'path_length']}
            rows.append(feats)
            texts.append(url)
    
    X_num = pd.DataFrame(rows).fillna(-1)
    print(f"Extracted {len(X_num.columns)} numerical features")
    return X_num, texts

def train_ensemble(csv_path="dataset.csv", use_network: bool = False):
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset not found at {csv_path}")
    
    print(f"Loading dataset from {csv_path}")
    df = pd.read_csv(csv_path)
    print(f"Dataset size: {len(df)} URLs")
    print(f"Class distribution: {df['label'].value_counts().to_dict()}")
    
    # Shuffle dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Extract features
    X_num, texts = prepare_features(df, use_network=use_network)
    y = df['label'].astype(int)
    
    # TF-IDF on URL strings (character n-grams)
    print("Creating TF-IDF features...")
    tfidf = TfidfVectorizer(
        analyzer='char_wb',
        ngram_range=(2, 5),
        max_features=5000,
        min_df=2,
        max_df=0.95
    )
    X_text = tfidf.fit_transform(texts)
    print(f"TF-IDF features: {X_text.shape[1]}")
    
    # Scale numerical features
    print("Scaling numerical features...")
    scaler = RobustScaler()  # More robust to outliers
    X_num_scaled = scaler.fit_transform(X_num)
    
    # Combine features
    print("Combining features...")
    X = hstack([csr_matrix(X_num_scaled), X_text])
    print(f"Total features: {X.shape[1]}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Get available models
    models = try_import_models()
    
    if len(models) >= 3:
        # Create ensemble with top 3 models
        print("Training ensemble model...")
        ensemble = VotingClassifier(
            estimators=models[:3],
            voting='soft',
            n_jobs=-1
        )
        
        # Train ensemble
        ensemble.fit(X_train, y_train)
        final_model = ensemble
        model_name = "ensemble"
    else:
        # Use single best model
        print("Training single model...")
        model_name, final_model = models[0]
        final_model.fit(X_train, y_train)
    
    # Evaluate model
    print("\\nEvaluating model...")
    train_score = final_model.score(X_train, y_train)
    test_score = final_model.score(X_test, y_test)
    
    y_pred = final_model.predict(X_test)
    y_proba = final_model.predict_proba(X_test)[:, 1] if hasattr(final_model, 'predict_proba') else None
    
    print(f"Train accuracy: {train_score:.4f}")
    print(f"Test accuracy: {test_score:.4f}")
    
    if y_proba is not None:
        auc_score = roc_auc_score(y_test, y_proba)
        print(f"AUC-ROC: {auc_score:.4f}")
    
    print("\\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
    
    print("\\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Save model
    os.makedirs(MODEL_DIR, exist_ok=True)
    artifacts = {
        'model': final_model,
        'tfidf': tfidf,
        'scaler': scaler,
        'numeric_columns': list(X_num.columns),
        'model_type': model_name,
        'feature_count': X.shape[1],
        'training_score': test_score
    }
    
    model_path = os.path.join(MODEL_DIR, MODEL_NAME)
    dump(artifacts, model_path)
    print(f"\\n[OK] Model saved to {model_path}")
    
    return final_model, test_score

if __name__ == "__main__":
    train_ensemble(csv_path="dataset.csv", use_network=False)