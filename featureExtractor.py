import whois
from urllib.parse import urlparse
import httpx
import pickle as pk
import pandas as pd
import extractorFunctions as ef


def get_domain_info(domain):
    """Fetch WHOIS info safely."""
    try:
        return whois.whois(domain)
    except Exception as e:
        print(f"[!] Failed to fetch WHOIS info for {domain}: {e}")
        return None


def featureExtraction(url: str) -> pd.DataFrame:
    """
    Extract features from a given URL.
    Returns a pandas DataFrame formatted for the ML model.
    """
    features = []

    # --- Address bar features ---
    features.append(ef.getLength(url))         # URL_Length
    features.append(ef.getDepth(url))          # URL_Depth
    features.append(ef.tinyURL(url))           # TinyURL
    features.append(ef.prefixSuffix(url))      # Prefix/Suffix
    features.append(ef.no_of_dots(url))        # No_Of_Dots
    features.append(ef.sensitive_word(url))    # Sensitive_Words

    # --- Domain features ---
    dns = 0
    domain_age, domain_end = 1, 1
    try:
        domain_info = get_domain_info(urlparse(url).netloc)
        if domain_info:
            domain_age = ef.domainAge(domain_info)
            domain_end = ef.domainEnd(domain_info)
    except Exception:
        dns = 1  # WHOIS failed

    features.append(1 if dns == 1 else domain_age)  # Domain_Age
    features.append(1 if dns == 1 else domain_end)  # Domain_End

    # --- HTML/JS features ---
    try:
        response = httpx.get(url, timeout=5)
    except Exception:
        response = ""

    dom_feats = [
        ef.iframe(response),
        ef.mouseOver(response),
        ef.forwarding(response)
    ]

    # Combine Unicode + @ sign + IP presence
    features.append(
        ef.has_unicode(url) +
        ef.haveAtSign(url) +
        ef.havingIP(url)
    )  # Have_Symbol

    # Apply PCA on dom features
    try:
        with open('model/pca_model.pkl', 'rb') as file:
            pca = pk.load(file)
        dom_pd = pd.DataFrame([dom_feats], columns=['iFrame', 'Mouse_Over', 'Web_Forwards'])
        pca_val = pca.transform(dom_pd)[0][0]
    except Exception as e:
        print(f"[!] PCA transform failed: {e}")
        pca_val = 0

    features.append(pca_val)  # domain_att

    # --- Final DataFrame ---
    feature_names = [
        'URL_Length', 'URL_Depth', 'TinyURL', 'Prefix/Suffix',
        'No_Of_Dots', 'Sensitive_Words', 'Domain_Age', 'Domain_End',
        'Have_Symbol', 'domain_att'
    ]

    row = pd.DataFrame([features], columns=feature_names)
    return row
