import pandas as pd
import random
from urllib.parse import urljoin

# Comprehensive dataset for better training
LEGITIMATE_URLS = [
    # Major tech companies
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.amazon.com",
    "https://www.facebook.com",
    "https://www.twitter.com",
    "https://www.linkedin.com",
    "https://www.instagram.com",
    "https://www.youtube.com",
    "https://www.netflix.com",
    "https://www.spotify.com",
    "https://www.adobe.com",
    "https://www.dropbox.com",
    "https://github.com",
    "https://stackoverflow.com",
    "https://www.reddit.com",
    "https://www.wikipedia.org",
    
    # Financial institutions
    "https://www.paypal.com",
    "https://www.chase.com",
    "https://www.bankofamerica.com",
    "https://www.wellsfargo.com",
    "https://www.citibank.com",
    
    # E-commerce
    "https://www.ebay.com",
    "https://www.etsy.com",
    "https://www.shopify.com",
    "https://www.walmart.com",
    "https://www.target.com",
    
    # News and media
    "https://www.cnn.com",
    "https://www.bbc.com",
    "https://www.nytimes.com",
    "https://www.reuters.com",
    
    # Educational
    "https://www.coursera.org",
    "https://www.edx.org",
    "https://www.khanacademy.org",
    
    # AI/ML platforms
    "https://huggingface.co/spaces/enzostvs/deepsite",
    "https://huggingface.co/models",
    "https://colab.research.google.com",
    "https://kaggle.com/datasets",
    "https://paperswithcode.com",
    
    # Developer platforms
    "https://github.com/microsoft/vscode",
    "https://gitlab.com/projects",
    "https://codepen.io/pen",
    "https://replit.com/@user/project",
    
    # Login pages (legitimate)
    "https://accounts.google.com/signin",
    "https://login.microsoftonline.com",
    "https://www.facebook.com/login",
    "https://twitter.com/login",
    "https://www.linkedin.com/login"
]

PHISHING_PATTERNS = [
    # Suspicious domains with brand names
    "https://paypal-security-{}.com",
    "https://amazon-account-{}.net",
    "https://apple-id-{}.org",
    "https://microsoft-security-{}.info",
    "https://google-verification-{}.co",
    "https://facebook-security-{}.tk",
    "https://twitter-suspended-{}.ml",
    "https://linkedin-account-{}.ga",
    "https://netflix-billing-{}.cf",
    "https://spotify-premium-{}.xyz",
    
    # Urgent action patterns
    "https://urgent-{}-verification.com",
    "https://immediate-{}-action.net",
    "https://suspended-{}-account.org",
    "https://expired-{}-login.info",
    "https://locked-{}-access.co",
    
    # Typosquatting
    "https://www.gooogle.com",
    "https://www.amazom.com",
    "https://www.paypaI.com",  # Capital i instead of l
    "https://www.microsft.com",
    "https://www.facebok.com",
    
    # IP addresses
    "http://192.168.1.{}/login",
    "https://10.0.0.{}/secure",
    "http://172.16.1.{}/verify",
    
    # Suspicious paths
    "https://legitimate-site.com/phishing/{}",
    "https://secure-{}.com/webscr/login",
    "https://update-{}.net/account/verify",
    
    # URL shorteners (suspicious context)
    "https://bit.ly/{}phish",
    "https://tinyurl.com/{}scam",
    "https://t.co/{}fake"
]

def generate_phishing_urls(count=100):
    urls = []
    for _ in range(count):
        pattern = random.choice(PHISHING_PATTERNS)
        if '{}' in pattern:
            # Generate random identifiers
            identifier = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=random.randint(3, 8)))
            url = pattern.format(identifier)
        else:
            url = pattern
        urls.append(url)
    return urls

def create_comprehensive_dataset():
    # Generate legitimate URLs (with some variations)
    legit_urls = LEGITIMATE_URLS.copy()
    
    # Add some legitimate variations
    for base_url in LEGITIMATE_URLS[:10]:
        legit_urls.extend([
            base_url + "/help",
            base_url + "/support",
            base_url + "/contact",
            base_url + "/about"
        ])
    
    # Generate phishing URLs
    phishing_urls = generate_phishing_urls(len(legit_urls))
    
    # Create dataset
    data = {
        'url': legit_urls + phishing_urls,
        'label': [0] * len(legit_urls) + [1] * len(phishing_urls)
    }
    
    df = pd.DataFrame(data)
    
    # Shuffle the dataset
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return df

if __name__ == "__main__":
    df = create_comprehensive_dataset()
    df.to_csv("dataset.csv", index=False)
    
    print(f"Dataset created successfully: dataset.csv")
    print(f"Total URLs: {len(df)}")
    print(f"Legitimate URLs: {sum(df['label'] == 0)}")
    print(f"Phishing URLs: {sum(df['label'] == 1)}")
    print(f"Balance: {sum(df['label'] == 0) / len(df) * 100:.1f}% legitimate")