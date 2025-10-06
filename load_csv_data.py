#!/usr/bin/env python3
"""
Load and prepare CSV phishing database for training
"""

import pandas as pd
import os

def load_phishing_csv(csv_path):
    """
    Load CSV file and prepare it for training
    Expected format: columns 'url' and 'label' (0=legitimate, 1=phishing)
    """
    
    if not os.path.exists(csv_path):
        print(f"Error: CSV file not found at {csv_path}")
        return None
    
    try:
        # Try to load the CSV
        df = pd.read_csv(csv_path)
        
        # Check if required columns exist
        if 'url' not in df.columns:
            # Try common column name variations
            url_cols = [col for col in df.columns if 'url' in col.lower()]
            if url_cols:
                df = df.rename(columns={url_cols[0]: 'url'})
            else:
                print("Error: No 'url' column found")
                print(f"Available columns: {list(df.columns)}")
                return None
        
        if 'label' not in df.columns:
            # Try common label column variations
            label_cols = [col for col in df.columns if any(x in col.lower() for x in ['label', 'class', 'target', 'phish'])]
            if label_cols:
                df = df.rename(columns={label_cols[0]: 'label'})
            else:
                print("Error: No 'label' column found")
                print(f"Available columns: {list(df.columns)}")
                return None
        
        # Clean the data
        df = df.dropna(subset=['url', 'label'])
        df['url'] = df['url'].astype(str)
        
        # Ensure labels are 0/1
        unique_labels = df['label'].unique()
        if len(unique_labels) == 2:
            if set(unique_labels) != {0, 1}:
                # Map to 0/1
                label_map = {unique_labels[0]: 0, unique_labels[1]: 1}
                df['label'] = df['label'].map(label_map)
        
        # Remove duplicates
        df = df.drop_duplicates(subset=['url'])
        
        print(f"Loaded {len(df)} URLs from {csv_path}")
        print(f"Legitimate: {sum(df['label'] == 0)}")
        print(f"Phishing: {sum(df['label'] == 1)}")
        
        return df
        
    except Exception as e:
        print(f"Error loading CSV: {e}")
        return None

def prepare_dataset(csv_path, output_path="dataset.csv"):
    """Load CSV and save as standardized dataset"""
    
    df = load_phishing_csv(csv_path)
    if df is None:
        return False
    
    # Save standardized dataset
    df[['url', 'label']].to_csv(output_path, index=False)
    print(f"Saved standardized dataset to {output_path}")
    
    return True

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        csv_path = input("Enter path to your CSV file: ").strip()
    else:
        csv_path = sys.argv[1]
    
    if prepare_dataset(csv_path):
        print("Dataset ready for training!")
        print("Run: python train_advanced.py")
    else:
        print("Failed to prepare dataset")