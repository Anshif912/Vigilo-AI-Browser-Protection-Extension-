import os
import sys
import pandas as pd
import numpy as np
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from xgboost import XGBClassifier

# Inject backend path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ml.feature_schema import URL_FEATURES, ALL_FEATURES
from ml.feature_extractor import extract_url_features, extract_page_features

router = APIRouter(prefix="/api/ml/analyze-url", tags=["Machine Learning Phishing Protection"])

# Resolve models paths
MODELS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "ml", "models"))
model_url_path = os.path.join(MODELS_DIR, "vigilo_phishing_xgb.json")
model_full_path = os.path.join(MODELS_DIR, "vigilo_phishing_full_xgb.json")
metadata_path = os.path.join(MODELS_DIR, "model_metadata.json")

# Load models
xgb_url = XGBClassifier()
if os.path.exists(model_url_path):
    xgb_url.load_model(model_url_path)
else:
    print(f"[Warning] ML URL-only model file not found at {model_url_path}")

xgb_full = XGBClassifier()
if os.path.exists(model_full_path):
    xgb_full.load_model(model_full_path)
else:
    print(f"[Warning] ML Full-page model file not found at {model_full_path}")

# Load feature importances from metadata if available
model_metadata = {}
if os.path.exists(metadata_path):
    try:
        with open(metadata_path, "r", encoding="utf-8") as f:
            import json
            model_metadata = json.load(f)
    except Exception:
        pass

class MLAnalyzeRequest(BaseModel):
    url: str = Field(..., example="https://google.com")
    html: Optional[str] = Field(None, description="Optional raw HTML content of the page for DOM feature analysis")

class FeatureExplanation(BaseModel):
    feature: str
    value: Any
    importance: float

class MLAnalyzeResponse(BaseModel):
    url: str
    prediction: str = Field(..., description="legitimate or phishing")
    phishing_probability: float = Field(..., description="Raw probability score of phishing risk (0.0 to 1.0)")
    features_extracted: Dict[str, Any] = Field(..., description="The features extracted from the URL and HTML")
    top_features: List[FeatureExplanation] = Field(..., description="Explanation list containing top features driving prediction")

@router.post("", response_model=MLAnalyzeResponse)
def analyze_url_ml(request: MLAnalyzeRequest) -> MLAnalyzeResponse:
    if not os.path.exists(model_url_path):
        raise HTTPException(status_code=500, detail="ML phishing model is not currently deployed.")
        
    try:
        # 1. Extract URL features
        url_feats = extract_url_features(request.url)
        
        # Determine mode based on html presence
        use_dom = request.html is not None and len(request.html.strip()) > 0
        
        if use_dom:
            if not os.path.exists(model_full_path):
                raise HTTPException(status_code=500, detail="ML URL+DOM model is not currently deployed.")
            # Extract DOM features
            dom_feats = extract_page_features(request.html, request.url)
            
            # Combine all features
            combined_feats = {}
            combined_feats.update(url_feats)
            combined_feats.update(dom_feats)
            
            # Vector matching schema order
            feat_vector = [combined_feats.get(f, np.nan) for f in ALL_FEATURES]
            pred_df = pd.DataFrame([feat_vector], columns=ALL_FEATURES)
            
            prob_legit = float(xgb_full.predict_proba(pred_df)[0, 1])
            phishing_probability = 1.0 - prob_legit
            features_dict = {f: combined_feats[f] for f in ALL_FEATURES if f in combined_feats}
            
            # Feature explanation
            full_importances = xgb_full.feature_importances_
            feat_imp_pairs = [
                {"feature": f, "value": combined_feats.get(f, "N/A"), "importance": float(imp)}
                for f, imp in zip(ALL_FEATURES, full_importances)
            ]
            top_explanations = sorted(feat_imp_pairs, key=lambda x: x["importance"], reverse=True)[:3]
            
        else:
            # URL-only features mode
            feat_vector = [url_feats[f] for f in URL_FEATURES]
            pred_df = pd.DataFrame([feat_vector], columns=URL_FEATURES)
            
            prob_legit = float(xgb_url.predict_proba(pred_df)[0, 1])
            phishing_probability = 1.0 - prob_legit
            features_dict = {f: url_feats[f] for f in URL_FEATURES if f in url_feats}
            
            # Feature explanation
            url_importances = xgb_url.feature_importances_
            feat_imp_pairs = [
                {"feature": f, "value": url_feats.get(f, "N/A"), "importance": float(imp)}
                for f, imp in zip(URL_FEATURES, url_importances)
            ]
            top_explanations = sorted(feat_imp_pairs, key=lambda x: x["importance"], reverse=True)[:3]
            
        prediction_label = "phishing" if phishing_probability >= 0.5 else "legitimate"
        
        return MLAnalyzeResponse(
            url=request.url,
            prediction=prediction_label,
            phishing_probability=phishing_probability,
            features_extracted=features_dict,
            top_features=[FeatureExplanation(**item) for item in top_explanations]
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Inference error: {str(e)}")
