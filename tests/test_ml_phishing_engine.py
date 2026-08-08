import sys
import os
import json
import pandas as pd
import numpy as np
from xgboost import XGBClassifier

# Inject backend path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from ml.feature_schema import ALL_FEATURES, URL_FEATURES, DOM_FEATURES
from ml.feature_extractor import extract_url_features, extract_page_features

def test_ml_pipeline():
    print("=" * 60)
    print("VIGILO ML TESTING & INTEGRITY SUITE")
    print("=" * 60)
    
    models_dir = "backend/ml/models"
    model_url_path = os.path.join(models_dir, "vigilo_phishing_xgb.json")
    model_full_path = os.path.join(models_dir, "vigilo_phishing_full_xgb.json")
    schema_path = os.path.join(models_dir, "feature_schema.json")
    metadata_path = os.path.join(models_dir, "model_metadata.json")
    metrics_path = os.path.join(models_dir, "metrics.json")
    
    # 1. Verify model artifacts generated
    assert os.path.exists(model_url_path), "URL-only model artifact not found!"
    assert os.path.exists(model_full_path), "Full URL+DOM model artifact not found!"
    assert os.path.exists(schema_path), "Feature schema not found!"
    assert os.path.exists(metadata_path), "Model metadata not found!"
    assert os.path.exists(metrics_path), "Metrics artifact not found!"
    print("[PASS] Model artifacts generation verified.")
    
    # 2. Verify feature schema compliance
    with open(schema_path, "r") as f:
        schema = json.load(f)
    assert schema["version"] == "4.2.0"
    assert "URLSimilarityIndex" not in schema["all_features"], "Leakage check failed: URLSimilarityIndex present in schema!"
    assert "FILENAME" not in schema["all_features"], "Leakage check failed: FILENAME present in schema!"
    assert "label" not in schema["all_features"], "Leakage check failed: label present in schema!"
    print("[PASS] Feature schema leakage checks verified.")
    
    # 3. Verify domain-aware split logic via metadata
    with open(metadata_path, "r") as f:
        meta = json.load(f)
    assert meta["train_test_domain_overlap"] == 0, "Domain leakage check failed: train/test domain overlap detected!"
    print("[PASS] Domain-aware train/test separation verified.")
    
    # 4. Load the trained XGBoost models
    xgb_url = XGBClassifier()
    xgb_url.load_model(model_url_path)
    
    xgb_full = XGBClassifier()
    xgb_full.load_model(model_full_path)
    print("[PASS] Both XGBoost models loaded successfully.")
    
    # 5. Legitimate regression cases (URL-only)
    legit_cases = [
        "https://google.com",
        "https://github.com",
        "https://ollama.com",
        "https://ollama.com/pricing",
        "https://ollama.com/pricing?utm_source=chatgpt",
        "https://github.com/login",
        "https://paypal.com/login",
        "https://microsoft.com/account",
        "https://huggingface.co"
    ]
    
    print("\nEvaluating Legitimate Regression Cases (URL-only model):")
    for url in legit_cases:
        url_feats = extract_url_features(url)
        feat_vector = [url_feats[f] for f in URL_FEATURES]
                
        pred_df = pd.DataFrame([feat_vector], columns=URL_FEATURES)
        prob = xgb_url.predict_proba(pred_df)[0, 1]  # Prob of legitimate class (label 1)
        phishing_prob = 1.0 - prob
        
        print(f"  URL: {url:<45} | Phishing Prob: {phishing_prob:.4f} | Prediction: {'LEGITIMATE' if prob >= 0.5 else 'PHISHING'}")
        assert prob >= 0.5, f"Legitimate regression case failed for {url}!"
        
    print("[PASS] Legitimate regression cases resolved correctly.")
    
    # 6. Phishing regression cases (URL-only)
    phishing_cases = [
        "https://g00gle-security-update.xyz",
        "https://sbi-kyc-update-portal.online",
        "https://secure-document-share-login.xyz",
        "https://google.com.example.org"
    ]
    
    print("\nEvaluating Phishing Regression Cases (URL-only model):")
    for url in phishing_cases:
        url_feats = extract_url_features(url)
        feat_vector = [url_feats[f] for f in URL_FEATURES]
                
        pred_df = pd.DataFrame([feat_vector], columns=URL_FEATURES)
        prob = xgb_url.predict_proba(pred_df)[0, 1]
        phishing_prob = 1.0 - prob
        
        print(f"  URL: {url:<45} | Phishing Prob: {phishing_prob:.4f} | Prediction: {'LEGITIMATE' if prob >= 0.5 else 'PHISHING'}")
        assert prob < 0.5, f"Phishing regression case failed for {url}!"
        
    print("[PASS] Phishing regression cases resolved correctly.")
    print("\n" + "=" * 60)
    print("ALL TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)

if __name__ == "__main__":
    test_ml_pipeline()
