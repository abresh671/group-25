import httpx
import whois
import tldextract
import numpy as np
from bs4 import BeautifulSoup
import requests

def safe_whois(domain):
    """Fetch WHOIS info, return None if fails"""
    try:
        w = whois.whois(domain)
        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        return expiration
    except Exception:
        return None

def featureExtraction(url):
    """
    Extract features from a URL for phishing detection.
    Returns a flattened 1D array of features.
    """
    features = []

    # Example features: length, dots, hyphens, tld, etc.
    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('-'))

    # Extract domain info
    ext = tldextract.extract(url)
    features.append(len(ext.domain))  # domain length
    features.append(len(ext.suffix))  # TLD length

    # WHOIS expiration (days from today, or 0 if fail)
    exp = safe_whois(url)
    if exp is None:
        features.append(0)
    else:
        from datetime import datetime
        if isinstance(exp, str):
            try:
                exp = datetime.strptime(exp, "%Y-%m-%d")
            except:
                exp = datetime.now()
        features.append((exp - datetime.now()).days)

    # You can add more features (HTTP response, soup analysis, etc.)
    try:
        r = requests.get(url, timeout=3)
        features.append(len(r.text))  # page length
        soup = BeautifulSoup(r.text, "html.parser")
        features.append(len(soup.find_all('a')))  # number of links
    except Exception:
        features.append(0)
        features.append(0)

    # Ensure features are returned as 1D numpy array
    return np.array(features).flatten()
