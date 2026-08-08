# VIGILO ML Model Card - Phishing Classifier v4.2

## Purpose
An independent experimental machine learning classifier to predict the phishing probability of URLs. Designed to generalize to unseen domains and act as a supporting signal in the Vigilo Threat Fusion Engine.

## Training Dataset
*   **Name**: PhiUSIIL Phishing URL Dataset
*   **Rows**: 235795
*   **Target Column**: `label` (1 = Legitimate, 0 = Phishing)

## Excluded Features
*   `URLSimilarityIndex`: Target leakage vector (100.0 constant score for all legitimate instances).
*   `FILENAME`: Dataset-only identifier.
*   `label`: Target class indicator.
*   `url_char_prob`: Prevent vocabulary memorization.
*   `char_continuation_rate`: Prevent vocabulary memorization.

## Preprocessing Configuration
*   URL Normalization: Standardized case normalization, URL decoding, duplicate slash cleaning, and Unicode NFKC normalization.
*   Feature Extraction: Deterministic matching schema shared between training and live inference.

## Evaluation Methodology
*   **Domain-Aware Splitting**: Unique registered domains grouped and isolated into Train (70%), Validation (15%), and Test (15%) partitions to prevent domain memorization.
*   **Evaluation splits**: Train: 165915 rows, Validation: 39322 rows, Test: 30558 rows.

## Model Performance (URL-only Model)
*   Accuracy: 0.9955
*   Precision: 0.9936
*   Recall: 0.9996
*   F1: 0.9966
*   ROC-AUC: 0.9974
*   False Positive Rate (FPR): 0.0124
*   False Negative Rate (FNR): 0.0004

## Top Features (URL-only Model)
1. **other_special_chars_count_in_url** (Importance: 0.4961)
2. **is_https** (Importance: 0.3285)
3. **subdomain_count** (Importance: 0.0527)
4. **digits_count_in_url** (Importance: 0.0330)
5. **url_length** (Importance: 0.0272)
6. **letter_ratio_in_url** (Importance: 0.0256)
7. **letters_count_in_url** (Importance: 0.0095)
8. **tld_legitimate_prob** (Importance: 0.0061)
9. **tld_length** (Importance: 0.0058)
10. **digit_ratio_in_url** (Importance: 0.0058)

## Live Inference Requirements
- Schema validation mapping identical to `feature_schema.json`.
- Excludes certificate analysis due to dataset structure limitations.
