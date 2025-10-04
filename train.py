import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.ensemble import RandomForestClassifier
import joblib
from featureExtractor import featureExtraction

DATASET_PATH = 'data/phishing.csv'

def prepare_data(dataset_path):
    df = pd.read_csv(dataset_path)
    features = []
    labels = []

    for index, row in df.iterrows():
        url = row['url']
        label = row['label']
        feat = featureExtraction(url)
        features.append(feat)
        labels.append(label)

    # Convert features to proper 2D numpy array
    features = np.array(features)
    features = features.reshape(features.shape[0], -1)  # flatten all extra dims

    return pd.DataFrame(features), np.array(labels)

if __name__ == "__main__":
    print("[*] Preparing data...")
    X, y = prepare_data(DATASET_PATH)

    print("[*] Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("[*] Applying PCA...")
    pca = PCA(n_components=min(10, X_scaled.shape[1]))
    X_pca = pca.fit_transform(X_scaled)

    print("[*] Training classifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_pca, y)

    # Save the full pipeline
    joblib.dump({
        'scaler': scaler,
        'pca': pca,
        'classifier': clf
    }, "phishingdetection.pkl")

    print("[+] Model saved as phishingdetection.pkl")
