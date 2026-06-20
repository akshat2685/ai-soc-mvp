import os
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
import joblib
import boto3
from botocore import UNSIGNED
from botocore.config import Config

MODELS_DIR = os.path.join(os.path.dirname(__file__), "ml_models")
os.makedirs(MODELS_DIR, exist_ok=True)
DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "scratch", "dataset.csv")
MODEL_PATH = os.path.join(MODELS_DIR, "network_model.pkl")

def download_dataset():
    if os.path.exists(DATASET_PATH):
        print(f"Dataset already exists at {DATASET_PATH}")
        return True
        
    print("Downloading CSE-CIC-IDS2018 dataset from AWS S3... (This may take a few minutes)")
    try:
        s3 = boto3.client('s3', region_name='ca-central-1', config=Config(signature_version=UNSIGNED))
        bucket_name = 'cse-cic-ids2018'
        object_key = 'Processed Traffic Data for ML Algorithms/Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv'
        
        s3.download_file(bucket_name, object_key, DATASET_PATH)
        print("Download complete.")
        return True
    except Exception as e:
        print(f"Failed to download dataset: {e}")
        return False

def train_model():
    print("Loading dataset into memory...")
    # Read a subset to prevent out-of-memory errors on local machine
    df = pd.read_csv(DATASET_PATH, nrows=200000)
    
    # Clean column names
    df.columns = df.columns.str.strip()
    
    print(f"Loaded {len(df)} rows. Labels: {df['Label'].unique()}")
    
    # Convert labels
    df['is_malicious'] = (df['Label'] != 'Benign').astype(int)
    
    features = [
        'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Fwd Packet Length Max', 'Fwd Packet Length Mean', 'Bwd Packet Length Max', 
        'Bwd Packet Length Mean', 'Flow Bytes/s', 'Flow Packets/s', 'Packet Length Mean',
        'Average Packet Size'
    ]
    
    # Clean inf/-inf
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    X = df[features]
    y = df['is_malicious']
    
    # Impute missing
    imputer = SimpleImputer(strategy='constant', fill_value=0)
    X = imputer.fit_transform(X)
    
    # Scale
    scaler = StandardScaler()
    X = scaler.fit_transform(X)
    
    print("Training Random Forest model...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    clf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    
    acc = clf.score(X_test, y_test)
    print(f"Model trained successfully. Accuracy: {acc*100:.2f}%")
    
    # Save model pipeline
    model_pipeline = {
        'features': features,
        'imputer': imputer,
        'scaler': scaler,
        'classifier': clf
    }
    joblib.dump(model_pipeline, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH}")

if __name__ == "__main__":
    if download_dataset():
        train_model()
