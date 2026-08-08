# VIGILO ML Phishing Detection Model Report

## Dataset
*   PhiUSIIL Phishing dataset containing 235795 rows and 56 features.

## Leakage Prevention
*   Strictly verified that target leakage indicators (`URLSimilarityIndex`, `FILENAME`, and target label) were dropped prior to training.

## Feature Schema
*   Schema contains 19 active URL features.

## Domain-Aware Split
*   Unique domains: 175509
*   Train unique domains: 122856
*   Validation unique domains: 26326
*   Test unique domains: 26327
*   Overlap: Train ∩ Test = 0 (Confirmed)

## Training Configuration
*   Model type: XGBoost Classifier
*   Objective: binary:logistic
*   Estimators: 100

## Unseen Test Metrics (URL-only Model)
*   Accuracy: 0.9955
*   Precision: 0.9936
*   Recall: 0.9996
*   F1: 0.9966
*   ROC-AUC: 0.9974
*   PR-AUC: 0.9978

## Confusion Matrix (URL-only Model)
*   TN: 10313
*   FP: 130
*   FN: 9
*   TP: 20106

## Top 10 Features
1. **other_special_chars_count_in_url** — Importance 0.4961
2. **is_https** — Importance 0.3285
3. **subdomain_count** — Importance 0.0527
4. **digits_count_in_url** — Importance 0.0330
5. **url_length** — Importance 0.0272
6. **letter_ratio_in_url** — Importance 0.0256
7. **letters_count_in_url** — Importance 0.0095
8. **tld_legitimate_prob** — Importance 0.0061
9. **tld_length** — Importance 0.0058
10. **digit_ratio_in_url** — Importance 0.0058

## Legitimate & Phishing Regression Tests
*   URL: `https://google.com` — Expected: **Legitimate**
*   URL: `https://github.com` — Expected: **Legitimate**
*   URL: `https://ollama.com` — Expected: **Legitimate**
*   URL: `https://ollama.com/pricing` — Expected: **Legitimate**
*   URL: `https://ollama.com/pricing?utm_source=chatgpt` — Expected: **Legitimate**
*   URL: `https://github.com/login` — Expected: **Legitimate**
*   URL: `https://paypal.com/login` — Expected: **Legitimate**
*   URL: `https://microsoft.com/account` — Expected: **Legitimate**
*   URL: `https://huggingface.co` — Expected: **Legitimate**
*   URL: `https://g00gle-security-update.xyz` — Expected: **Phishing**
*   URL: `https://sbi-kyc-update-portal.online` — Expected: **Phishing**
*   URL: `https://secure-document-share-login.xyz` — Expected: **Phishing**
*   URL: `https://google.com.example.org` — Expected: **Phishing**

## Limitations
- Excludes certificate analysis due to dataset structure limitations.
