# MShield: Advanced XSS Checker for Bug Bounties
import re
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
import pickle
import urllib.parse

# Comprehensive XSS payload patterns
XSS_PATTERNS = [
    r'<\s*script\b[^>]*>[^<]*<\s*/\s*script\s*>',  # <script>...</script>
    r'on\w+\s*=\s*["\'][^"\']*["\']',              # on* events (e.g., onerror='alert(1)')
    r'javascript\s*:[^"\']*',                      # javascript: URLs
    r'<\s*img\s+[^>]*src\s*=\s*["\']?[^"\']*["\']',# <img src=...>
    r'<\s*(iframe|embed|object)\b',                # Dangerous tags
    r'%3C\s*script',                               # Encoded <script
    r'document\.\w+',                              # JS functions (e.g., document.write)
    r'alert\s*\(',                                 # alert(
    r'eval\s*\(',                                  # eval(
    r'<\s*[a-zA-Z]+\s+[^>]*>',                     # Generic HTML tags with attributes
]

def extract_features(input_string):
    """Extract features for XSS detection."""
    decoded = urllib.parse.unquote(input_string)  # Decode URL-encoded strings
    features = {
        'length': len(decoded),
        'script_count': len(re.findall(r'<script\b', decoded, re.IGNORECASE)),
        'on_event_count': len(re.findall(r'on\w+\s*=', decoded, re.IGNORECASE)),
        'special_chars': sum(c in '<>"\'&;%' for c in decoded),
        'js_function_count': len(re.findall(r'(alert|eval|document\.\w+)\s*\(', decoded, re.IGNORECASE)),
        'url_encoded': 1 if input_string != decoded else 0,
        'tag_count': len(re.findall(r'<\s*[a-zA-Z]+', decoded, re.IGNORECASE)),
    }
    return features

def check_xss_regex(input_string):
    """Check for XSS using regex patterns."""
    decoded = urllib.parse.unquote(input_string)
    for pattern in XSS_PATTERNS:
        if re.search(pattern, decoded, re.IGNORECASE):
            return f"XSS Detected: Matches pattern '{pattern}'"
    return "No XSS Detected (Regex)"

def train_xss_model():
    """Train a simple Logistic Regression model."""
    # Synthetic dataset (expand with Kaggle data later)
    data = [
        {'input': '<script>alert(1)</script>', 'label': 1},
        {'input': '<img src=x onerror=alert(1)>', 'label': 1},
        {'input': 'javascript:alert(1)', 'label': 1},
        {'input': '%3Cscript%3Ealert(1)%3C/script%3E', 'label': 1},
        {'input': 'Hello world', 'label': 0},
        {'input': 'Search query', 'label': 0},
        {'input': '<p>Safe text</p>', 'label': 0},
        {'input': 'User input', 'label': 0},
    ]
    df = pd.DataFrame(data)
    features = df['input'].apply(extract_features)
    feature_df = pd.DataFrame(features.tolist())
    X = feature_df
    y = df['label']

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Train model
    model = LogisticRegression(random_state=42)
    model.fit(X_scaled, y)

    # Save model and scaler
    with open('mshield_xss_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    with open('mshield_scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    
    return model, scaler

def predict_xss(input_string, model, scaler):
    """Predict XSS using ML model."""
    features = extract_features(input_string)
    feature_df = pd.DataFrame([features])
    X_scaled = scaler.transform(feature_df)
    prob = model.predict_proba(X_scaled)[0][1]  # Probability of XSS
    prediction = model.predict(X_scaled)[0]
    result = "XSS Detected" if prediction == 1 else "No XSS Detected"
    return f"{result} (ML Confidence: {prob:.2%})"

def mshield_xss_check(input_string):
    """Combine regex and ML for robust XSS detection."""
    # Regex check
    regex_result = check_xss_regex(input_string)
    
    # ML check
    try:
        with open('mshield_xss_model.pkl', 'rb') as f:
            model = pickle.load(f)
        with open('mshield_scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
    except FileNotFoundError:
        model, scaler = train_xss_model()
    
    ml_result = predict_xss(input_string, model, scaler)
    
    # Combine results (XSS if either detects)
    if "XSS Detected" in regex_result or "XSS Detected" in ml_result:
        return {
            'input': input_string,
            'regex_result': regex_result,
            'ml_result': ml_result,
            'final_result': 'XSS Detected',
            'report': f"MShield XSS Report\nInput: {input_string}\nRegex: {regex_result}\nML: {ml_result}\nRecommendation: Sanitize input to prevent XSS."
        }
    return {
        'input': input_string,
        'regex_result': regex_result,
        'ml_result': ml_result,
        'final_result': 'No XSS Detected',
        'report': f"MShield XSS Report\nInput: {input_string}\nResult: Safe input."
    }

# Test inputs
if __name__ == "__main__":
    test_inputs = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "Hello world",
        "<p>Safe text</p>",
        "Search query",
        "User input",
        "<iframe src='http://malicious.com'></iframe>",
        "<object data='http://malicious.com'></object>",
        "<svg onload=alert(1)>",    
        "<a href='javascript:alert(1)'>Click me</a>",
        "<style>@import'http://malicious.com'</style>",
        "<div style='background-image: url(javascript:alert(1))'>",
        "<body onload='alert(1)'>",
        "<!-- <script>alert(1)</script> -->",
    ]
    
    for inp in test_inputs:
        result = mshield_xss_check(inp)
        print(f"\nInput: {result['input']}")
        print(f"Regex Result: {result['regex_result']}")
        print(f"ML Result: {result['ml_result']}")
        print(f"Final Result: {result['final_result']}")
        print(f"Report:\n{result['report']}\n")