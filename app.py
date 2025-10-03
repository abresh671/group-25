"""
app.py

Flask web application for Hooked – Phishing Detection Toolkit.
Users can submit a URL through the web interface and receive a prediction.
"""

import logging
<<<<<<< HEAD
from flask import Flask, request, render_template, jsonify
=======
from flask import Flask, render_template, request
>>>>>>> 31e62cff7e4739e8418af30b752744faf0d77ab1
from urllib.parse import urlparse
from featureExtractor import featureExtraction
from pycaret.classification import load_model, predict_model
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

app = Flask(__name__)


def load_phishing_model(model_path: str):
    """
    Load the pre-trained phishing detection model.
    Tries both with and without '.pkl' extension.
    """
    try:
        if os.path.exists(model_path + ".pkl"):
            model = load_model(model_path)
        elif os.path.exists(model_path):
            model = load_model(model_path)
        else:
            raise FileNotFoundError(f"Model file not found at {model_path}")
        logging.info("Model loaded successfully from '%s'", model_path)
        return model
    except Exception as e:
        logging.error("Failed to load model: %s", str(e))
        raise RuntimeError(f"Failed to load model at '{model_path}'.")


def validate_url(url: str) -> bool:
    """
    Validate the given URL format.
    """
    parsed = urlparse(url)
    return bool(parsed.scheme and parsed.netloc)


def predict(url: str, model):
    """
    Predict whether a URL is phishing or safe.
    """
    if not validate_url(url):
        logging.warning("Invalid URL submitted: %s", url)
        return {"error": "Invalid URL format"}

    try:
        data = featureExtraction(url)
        result = predict_model(model, data=data)

        # Handle PyCaret version differences
        label_col = "prediction_label" if "prediction_label" in result.columns else "Label"
        score_col = "prediction_score" if "prediction_score" in result.columns else "Score"

        prediction_label = result[label_col][0]
        prediction_score = float(result[score_col][0]) * 100

        logging.info("URL analyzed: %s | Label: %s | Score: %.2f%%",
                     url, prediction_label, prediction_score)

        return {
            'prediction_label': prediction_label,
            'prediction_score': prediction_score
        }
    except Exception as e:
        logging.error("Error during prediction for URL '%s': %s", url, str(e))
        return {"error": f"Prediction failed: {str(e)}"}


# Load model globally
model = load_phishing_model('model/phishingdetection')


@app.route('/')
def index():
    """Render the main page with URL input form."""
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    """Handle URL submission and return prediction results."""
    url = request.form.get('url', '').strip()
    result = predict(url, model)

    if "error" in result:
        return render_template('result.html', url=url, error=result["error"])
    else:
        return render_template(
<<<<<<< HEAD
            'index.html',
=======
            'result.html',
>>>>>>> 31e62cff7e4739e8418af30b752744faf0d77ab1
            url=url,
            label=result['prediction_label'],
            score=round(result['prediction_score'], 2)
        )


if __name__ == "__main__":
    # Start the Flask web server
    app.run(host='0.0.0.0', port=5000, debug=True)
