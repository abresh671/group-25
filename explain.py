import numpy as np
import shap
try:
    from predict_advanced import load_artifacts, url_to_features
except ImportError:
    print("Error: predict_advanced module not found")
    import sys
    sys.exit(1)

def explain_url(url: str, top_k: int = 8, use_network: bool = False):
    try:
        model, tfidf, scaler, numeric_cols = load_artifacts()
        X = url_to_features(url, tfidf, scaler, numeric_cols, use_network=use_network)
        
        if hasattr(X, 'toarray'):
            X = X.toarray()
        
        # Handle VotingClassifier by using first estimator
        if hasattr(model, 'estimators_'):
            base_model = model.estimators_[0]
        else:
            base_model = model
        
        explainer = shap.TreeExplainer(base_model)
        shap_values = explainer.shap_values(X)
        
        sv = shap_values[1][0] if isinstance(shap_values, list) else shap_values[0]
        feature_names = list(numeric_cols) + list(tfidf.get_feature_names_out())
        
        idx = np.argsort(-np.abs(sv))[:top_k]
        return [(feature_names[i], float(sv[i])) for i in idx]
    
    except Exception as e:
        print(f"Error: {e}")
        return []

if __name__ == "__main__":
    url = input("URL: ").strip()
    if not url:
        print("No URL provided")
        exit(1)
    
    results = explain_url(url)
    if results:
        print("\nTop features influencing prediction:")
        for name, val in results:
            print(f"{name}: {val:+.4f}")
    else:
        print("No results to display")
