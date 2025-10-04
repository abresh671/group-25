import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
import os

# -----------------------------
# Step 1: Load your dataset
# -----------------------------
csv_path = os.path.join("data", "phishing.csv")  # updated path
data = pd.read_csv(csv_path)

# Ensure the CSV has columns: "url" and "label" (0 = benign, 1 = phishing)

# -----------------------------
# Step 2: Feature extraction
# -----------------------------
# Simple features: URL length + number of dots
def extract_features(url):
    return [len(url), url.count('.')]

X = data['url'].apply(extract_features).tolist()
y = data['label']

# -----------------------------
# Step 3: Train/test split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# -----------------------------
# Step 4: Train model
# -----------------------------
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# -----------------------------
# Step 5: Evaluate
# -----------------------------
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"Test Accuracy: {acc*100:.2f}%")

# -----------------------------
# Step 6: Save the model
# -----------------------------
joblib.dump(model, "phishingdetection.pkl")
print("New model saved as phishingdetection.pkl")
