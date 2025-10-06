from flask import Flask, request, render_template_string, jsonify, send_from_directory
from predict_advanced import load_artifacts, url_to_features, predict, predict_batch, get_model_info
from explain import explain_url
import os
import json
from datetime import datetime

app = Flask(__name__)

# Try to load model at startup
try:
    model, tfidf, scaler, numeric_cols = load_artifacts()
    model_loaded = True
    print("✅ Model loaded successfully")
except FileNotFoundError:
    print("❌ Model not found. Please run train_advanced.py first.")
    model = tfidf = scaler = numeric_cols = None
    model_loaded = False

# Enhanced HTML template with modern UI
ADVANCED_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Phishing Detection System</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .card-hover:hover { transform: translateY(-5px); transition: all 0.3s; }
        .result-safe { color: #28a745; }
        .result-danger { color: #dc3545; }
        .feature-item { font-size: 0.9em; margin: 2px 0; }
        .loading { display: none; }
        .batch-results { max-height: 400px; overflow-y: auto; }
    </style>
</head>
<body class="bg-light">
    <nav class="navbar navbar-dark gradient-bg">
        <div class="container">
            <span class="navbar-brand mb-0 h1">
                <i class="fas fa-shield-alt"></i> Advanced Phishing Detection System
            </span>
            <a href="https://github.com/abresh671/group-25" class="btn btn-outline-light btn-sm" target="_blank">
                <i class="fab fa-github"></i> View on GitHub
            </a>
            <span class="navbar-text">
                {% if model_info %}
                    Model: {{ model_info.model_type }} | Features: {{ model_info.feature_count }}
                {% else %}
                    Model: Not Loaded
                {% endif %}
            </span>
        </div>
    </nav>

    <div class="container mt-4">
        <!-- Single URL Analysis -->
        <div class="row">
            <div class="col-md-8 mx-auto">
                <div class="card card-hover shadow">
                    <div class="card-header">
                        <h5><i class="fas fa-search"></i> Single URL Analysis</h5>
                    </div>
                    <div class="card-body">
                        <form method="post" id="singleForm">
                            <div class="input-group mb-3">
                                <input name="url" class="form-control" placeholder="Enter URL to analyze (e.g., https://www.kaggle.com/datasets/akashkr/phishing-website-dataset)" 
                                       value="{{ url or 'https://www.kaggle.com/datasets/akashkr/phishing-website-dataset' }}" required>
                                <button class="btn btn-primary" type="submit">
                                    <i class="fas fa-search"></i> Analyze
                                </button>
                            </div>
                        </form>
                        
                        <div class="loading text-center">
                            <div class="spinner-border" role="status"></div>
                            <p>Analyzing URL...</p>
                        </div>

                        {% if result %}
                        <div class="alert {{ 'alert-danger' if result=='PHISHING' else 'alert-success' }} mt-3">
                            <h6>
                                <i class="fas {{ 'fa-exclamation-triangle' if result=='PHISHING' else 'fa-check-circle' }}"></i>
                                Result: <strong>{{ result }}</strong>
                                {% if score %}(Confidence: {{ "%.1f"|format(score * 100) }}%){% endif %}
                            </h6>
                        </div>
                        
                        {% if expl %}
                        <div class="card mt-3">
                            <div class="card-header">
                                <h6><i class="fas fa-chart-bar"></i> Feature Analysis</h6>
                            </div>
                            <div class="card-body">
                                {% for feature in expl %}
                                <div class="feature-item">
                                    <span class="badge bg-secondary">{{ feature }}</span>
                                </div>
                                {% endfor %}
                            </div>
                        </div>
                        {% endif %}
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>

        <!-- Batch Analysis -->
        <div class="row mt-4">
            <div class="col-md-8 mx-auto">
                <div class="card card-hover shadow">
                    <div class="card-header">
                        <h5><i class="fas fa-list"></i> Batch URL Analysis</h5>
                    </div>
                    <div class="card-body">
                        <form id="batchForm">
                            <div class="mb-3">
                                <textarea class="form-control" id="batchUrls" rows="5" 
                                          placeholder="Enter multiple URLs (one per line)"></textarea>
                            </div>
                            <button type="submit" class="btn btn-info">
                                <i class="fas fa-tasks"></i> Analyze Batch
                            </button>
                        </form>
                        
                        <div id="batchResults" class="mt-3"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- GitHub Repository Card -->
        <div class="row mt-4">
            <div class="col-md-8 mx-auto">
                <div class="card card-hover shadow">
                    <div class="card-header">
                        <h5><i class="fab fa-github"></i> Open Source Project</h5>
                    </div>
                    <div class="card-body">
                        <div class="row align-items-center">
                            <div class="col-md-8">
                                <h6>Advanced Phishing Detection System</h6>
                                <p class="text-muted mb-2">A comprehensive ML system for phishing URL detection with advanced feature extraction and explainable AI.</p>
                                <div class="d-flex gap-2">
                                    <span class="badge bg-primary">Python</span>
                                    <span class="badge bg-success">Machine Learning</span>
                                    <span class="badge bg-info">Flask</span>
                                    <span class="badge bg-warning text-dark">SHAP</span>
                                </div>
                            </div>
                            <div class="col-md-4 text-center">
                                <a href="https://github.com/abresh671/group-25" class="btn btn-dark btn-lg" target="_blank">
                                    <i class="fab fa-github"></i> View Repository
                                </a>
                                <div class="mt-2">
                                    <small class="text-muted">⭐ Star this project</small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Statistics -->
        <div class="row mt-4">
            <div class="col-md-4">
                <div class="card text-center card-hover shadow">
                    <div class="card-body">
                        <i class="fas fa-shield-alt fa-2x text-primary"></i>
                        <h5 class="mt-2">Protected</h5>
                        <p class="text-muted">Advanced ML Detection</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-center card-hover shadow">
                    <div class="card-body">
                        <i class="fas fa-brain fa-2x text-success"></i>
                        <h5 class="mt-2">AI-Powered</h5>
                        <p class="text-muted">Machine Learning Analysis</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card text-center card-hover shadow">
                    <div class="card-body">
                        <i class="fas fa-chart-line fa-2x text-info"></i>
                        <h5 class="mt-2">Explainable</h5>
                        <p class="text-muted">SHAP Feature Analysis</p>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Batch analysis
        document.getElementById('batchForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const urls = document.getElementById('batchUrls').value.split('\\n').filter(url => url.trim());
            if (urls.length === 0) {
                alert('Please enter at least one URL');
                return;
            }
            
            const resultsDiv = document.getElementById('batchResults');
            resultsDiv.innerHTML = '<div class="text-center"><div class="spinner-border"></div><p>Processing...</p></div>';
            
            try {
                const response = await fetch('/api/batch', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ urls: urls })
                });
                
                const data = await response.json();
                
                let html = '<div class="batch-results"><h6>Results:</h6>';
                data.results.forEach(result => {
                    const status = result.prediction === 1 ? 'PHISHING' : 'LEGITIMATE';
                    const badgeClass = result.prediction === 1 ? 'bg-danger' : 'bg-success';
                    const confidence = result.probability ? `(${(result.probability * 100).toFixed(1)}%)` : '';
                    
                    html += `
                        <div class="d-flex justify-content-between align-items-center border-bottom py-2">
                            <small class="text-truncate" style="max-width: 60%;">${result.url}</small>
                            <span class="badge ${badgeClass}">${status} ${confidence}</span>
                        </div>
                    `;
                });
                html += '</div>';
                
                resultsDiv.innerHTML = html;
            } catch (error) {
                resultsDiv.innerHTML = '<div class="alert alert-danger">Error processing batch</div>';
            }
        });
        
        // Loading animation for single form
        document.getElementById('singleForm').addEventListener('submit', function() {
            document.querySelector('.loading').style.display = 'block';
        });
    </script>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    score = None
    expl = []
    url = ""
    
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            if not model_loaded:
                result = "ERROR: Model not loaded"
                expl = ["Please run train_advanced.py first"]
            else:
                try:
                    pred, proba = predict(url, use_network=False)
                    if pred is not None:
                        result = "PHISHING" if pred == 1 else "LEGITIMATE"
                        score = proba
                        
                        # Get explanations
                        try:
                            expl_pairs = explain_url(url, top_k=8, use_network=False)
                            expl = [f"{name} ({val:+.3f})" for name, val in expl_pairs]
                        except Exception as e:
                            expl = [f"Explanation not available: {e}"]
                    else:
                        result = "ERROR"
                        expl = ["Prediction failed"]
                except Exception as e:
                    result = "ERROR"
                    expl = [str(e)]
    
    model_info = get_model_info() if model_loaded else None
    return render_template_string(ADVANCED_HTML, 
                                result=result, 
                                score=score, 
                                expl=expl, 
                                url=url,
                                model_info=model_info)

@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.json or {}
    url = data.get("url")
    
    if not url:
        return jsonify({"error": "url missing"}), 400
    
    if not model_loaded:
        return jsonify({"error": "model not loaded"}), 500
    
    try:
        pred, proba = predict(url, use_network=data.get("use_network", False))
        if pred is not None:
            return jsonify({
                "url": url,
                "prediction": pred,
                "label": "PHISHING" if pred == 1 else "LEGITIMATE",
                "probability": proba,
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({"error": "prediction failed"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
        return jsonify({
            "results": results,
            "total": len(urls),
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

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "model_loaded": model_loaded,
        "timestamp": datetime.now().isoformat()
    })

if __name__ == "__main__":
    print("🚀 Starting Advanced Phishing Detection System")
    print(f"Model loaded: {model_loaded}")
    print("Access the web interface at: http://127.0.0.1:5000")
    
    app.run(host="127.0.0.1", port=5000, debug=True)