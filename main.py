import sys
import logging
from urllib.parse import urlparse
from featureExtractor import featureExtraction
from pycaret.classification import load_model, predict_model

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def load_phishing_model(model_path: str):
    """
    Load the pre-trained phishing detection model.

    Args:
        model_path (str): Path to the PyCaret model.

    Returns:
        model: Loaded PyCaret model.
    """
    try:
        model = load_model(model_path)
        logging.info("Model loaded successfully from '%s'", model_path)
        return model
    except Exception as e:
        logging.error("Failed to load model: %s", str(e))
        sys.exit(1)


def validate_url(url: str) -> bool:
    """
    Check if the URL is valid.
    """
    parsed = urlparse(url)
    return bool(parsed.scheme and parsed.netloc)


def predict(url: str, model) -> dict:
    """
    Predict whether a URL is phishing or safe using the loaded model.

    Args:
        url (str): URL to analyze
        model: Loaded PyCaret model

    Returns:
        dict: {'prediction_label': str, 'prediction_score': float}
    """
    if not validate_url(url):
        logging.warning("Invalid URL submitted: %s", url)
        return {"error": "Invalid URL format"}

    try:
        data = featureExtraction(url)
        result = predict_model(model, data=data)

        # Safe access to result keys
        prediction_label = result.get('prediction_label')[0] if 'prediction_label' in result else "Unknown"
        prediction_score = result.get('prediction_score')[0] * 100 if 'prediction_score' in result else 0

        logging.info("URL analyzed: %s | Label: %s | Score: %.2f%%",
                     url, prediction_label, prediction_score)

        return {
            'prediction_label': prediction_label,
            'prediction_score': prediction_score
        }

    except Exception as e:
        logging.error("Error predicting URL '%s': %s", url, str(e))
        return {"error": str(e)}


if __name__ == "__main__":
    # Load the model once
    model = load_phishing_model('model/phishingdetection')

    # Test URLs
    test_urls = [
        'https://bafybeifqd2yktzvwjw5g42l2ghvxsxn76khhsgqpkaqfdhnqf3kiuiegw4.ipfs.dweb.link/',
        'http://about-ads-microsoft-com.o365.frc.skyfencenet.com',
        'https://chat.openai.com',
        'https://github.com/'
    ]

    # Predict each URL
    for url in test_urls:
        result = predict(url, model)
        print(f"URL: {url}\nResult: {result}\n")
