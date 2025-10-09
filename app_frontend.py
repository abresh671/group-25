from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from predict_advanced import load_artifacts, url_to_features, predict, predict_batch, get_model_info
from explain import explain_url
import os
import json
from datetime import datetime

app = Flask(__name__)
CORS(app)  # Enable CORS for React frontend

# Try to load model at startup
try:
    model, tfidf, scaler, numeric_cols = load_artifacts()
    model_loaded = True
    print("[OK] Model loaded successfully")
except FileNotFoundError:
    print("[ERROR] Model not found. Please run train_advanced.py first.")
    model = tfidf = scaler = numeric_cols = None
    model_loaded = False

# Serve React frontend
@app.route("/")
def serve_frontend():
    return send_from_directory("frontend/dist", "index.html")

@app.route("/<path:path>")
def serve_static(path):
    if os.path.exists(f"frontend/dist/{path}"):
        return send_from_directory("frontend/dist", path)
    return send_from_directory("frontend/dist", "index.html")

# API Routes
@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.json or {}
    url = data.get("url")
    
    if not url:
        return jsonify({"error": "url missing"}), 400
    
    if not model_loaded:
        return jsonify({"error": "model not loaded"}), 500
    
    try:
        result = predict(url, use_network=data.get("use_network", True), include_advice=True)
        if len(result) == 3:  # With advice
            pred, proba, advice = result
        else: # Without advice (fallback)
            pred, proba = result
            advice = []
        
        if pred is not None:
            return jsonify({
                "url": url,
                "prediction": pred,
                "label": "HOOKED" if pred == 1 else "SAFE",
                "probability": proba,
                "confidence": proba * 100 if proba else 0,
                "timestamp": datetime.now().isoformat(),
                "message": "This URL is trying to hook you!" if pred == 1 else "You're safe from this hook!",
                "advice": advice,
                "analysis": "\n".join(advice) if advice else "No detailed analysis available"
            })
        else:
            return jsonify({"error": "prediction failed - unable to analyze URL"}), 500
    except Exception as e:
        return jsonify({"error": f"analysis error: {str(e)}"}), 500

@app.route("/api/batch", methods=["POST"])
def api_batch():
    data = request.json or {}
    urls = data.get("urls", [])
    
    if not urls:
        return jsonify({"error": "urls missing"}), 400
    
    if not model_loaded:
        return jsonify({"error": "model not loaded"}), 500
    
    try:
        results = predict_batch(urls, use_network=data.get("use_network", False))
        # Add confidence percentage
        for result in results:
            if result.get('probability'):
                result['confidence'] = result['probability'] * 100
        
        return jsonify({
            "results": results,
            "total": len(urls),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/explain", methods=["POST"])
def api_explain():
    data = request.json or {}
    url = data.get("url")
    
    if not url:
        return jsonify({"error": "url missing"}), 400
    
    if not model_loaded:
        return jsonify({"error": "model not loaded"}), 500
    
    try:
        explanations = explain_url(url, top_k=10, use_network = False)
        return jsonify({
            "url": url,
            "explanations": [{"feature": name, "value": float(val)} for name, val in explanations],
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/model/info", methods=["GET"])
def api_model_info():
    if not model_loaded:
        return jsonify({"error": "model not loaded"}), 500
    
    info = get_model_info()
    return jsonify(info)

@app.route("/api/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "model_loaded": model_loaded,
        "timestamp": datetime.now().isoformat()
    })

if __name__ == "__main__":
    print("[INFO] Starting Hooked Backend")
    print(f"Model loaded: {model_loaded}")
    print("Hooked Frontend will be served at: http://127.0.0.1:5000")
    
    app.run(host="127.0.0.1", port=5000, debug=True)