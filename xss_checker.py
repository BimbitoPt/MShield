# MShield: Enhanced XSS Checker for Bug Bounties (Version 2)
import re
import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
import pickle
import urllib.parse
import argparse
import json
import csv
import logging

# Setup logging for debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Comprehensive XSS payload patterns
XSS_PATTERNS = [
    r'<\s*script\b[^>]*>[^<]*<\s*/\s*script\s*>',  # <script>...</script>
    r'on\w+\s*=\s*["\'][^"\']*["\']',              # on* events (e.g., onerror='alert(1)')
    r'javascript\s*:[^"\']*',                      # javascript: URLs
    r'<\s*(img|iframe|embed|object)\b',            # Dangerous tags
    r'%3C\s*script|%3C\s*img',                     # Encoded <script, <img
    r'document\.\w+',                              # JS functions (e.g., document.write)
    r'(alert|prompt|confirm)\s*\(',                # JS alert/prompt/confirm
    r'eval\s*\(',                                  # eval(
    r'<\s*[a-zA-Z]+\s+[^>]*>',                     # Generic HTML tags with attributes
    r'data\s*:\s*[^,\s]+,',                        # data: URLs
    r'<\s*svg\b[^>]*>[^<]*<\s*/\s*svg\s*>',       # SVG tags
    r'vbscript\s*:[^"\']*',                        # vbscript: URLs
]

def extract_features(input_string):
    """Extract features for XSS detection."""
    decoded = urllib.parse.unquote(input_string)
    features = {
        'length': len(decoded),
        'script_count': len(re.findall(r'<script\b', decoded, re.IGNORECASE)),
        'on_event_count': len(re.findall(r'on\w+\s*=', decoded, re.IGNORECASE)),
        'special_chars': sum(c in '<>"\'&;%' for c in decoded),
        'js_function_count': len(re.findall(r'(alert|prompt|confirm|eval|document\.\w+)\s*\(', decoded, re.IGNORECASE)),
        'url_encoded': 1 if input_string != decoded else 0,
        'tag_count': len(re.findall(r'<\s*[a-zA-Z]+', decoded, re.IGNORECASE)),
        'quote_count': decoded.count('"') + decoded.count("'"),
        'encoded_char_count': len(re.findall(r'%[0-9A-Fa-f]{2}', decoded)),
        'html_entity_count': len(re.findall(r'&#\d+;', decoded)),
        'case_obfuscation': 1 if re.search(r'[a-zA-Z]+', decoded) and decoded != decoded.lower() else 0,
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
    """Train Logistic Regression model for XSS."""
    # Expanded synthetic dataset
    data = [
        {'input': '<script>alert(1)</script>', 'label': 1},
        {'input': '<img src=x onerror=alert(1)>', 'label': 1},
        {'input': 'javascript:alert(1)', 'label': 1},
        {'input': '%3Cscript%3Ealert(1)%3C/script%3E', 'label': 1},
        {'input': '<svg onload=alert(1)>', 'label': 1},
        {'input': '<input onfocus=alert(1)>', 'label': 1},
        {'input': 'vbscript:alert(1)', 'label': 1},
        {'input': 'data:text/html,<script>alert(1)</script>', 'label': 1},
        {'input': '<ScRiPt>alert(1)</ScRiPt>', 'label': 1},
        {'input': 'Hello world', 'label': 0},
        {'input': 'Search query', 'label': 0},
        {'input': '<p>Safe text</p>', 'label': 0},
        {'input': 'User input', 'label': 0},
        {'input': 'Login page', 'label': 0},
        {'input': 'Product search', 'label': 0},
        {'input': '<div>Content</div>', 'label': 0},
        {'input': 'Safe & sound', 'label': 0},
        {'input': 'Normal text', 'label': 0},
    ]
    df = pd.DataFrame(data)
    features = df['input'].apply(extract_features)
    feature_df = pd.DataFrame(features.tolist())
    X = feature_df
    y = df['label']

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = LogisticRegression(random_state=42, C=0.5)
    model.fit(X_scaled, y)

    with open('mshield_xss_model_v2.pkl', 'wb') as f:
        pickle.dump(model, f)
    with open('mshield_scaler_v2.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    
    logging.info("XSS model trained and saved.")
    return model, scaler

def predict_xss(input_string, model, scaler):
    """Predict XSS using ML model."""
    try:
        features = extract_features(input_string)
        feature_df = pd.DataFrame([features])
        X_scaled = scaler.transform(feature_df)
        prob = model.predict_proba(X_scaled)[0][1]
        prediction = model.predict(X_scaled)[0]
        result = "XSS Detected" if prediction == 1 else "No XSS Detected"
        return f"{result} (ML Confidence: {prob:.2%})"
    except Exception as e:
        logging.error(f"ML prediction failed: {str(e)}")
        return f"ML Error: {str(e)}"

def mshield_xss_check(input_string):
    """Check input for XSS vulnerabilities."""
    try:
        # Load or train model
        try:
            with open('mshield_xss_model_v2.pkl', 'rb') as f:
                model = pickle.load(f)
            with open('mshield_scaler_v2.pkl', 'rb') as f:
                scaler = pickle.load(f)
        except FileNotFoundError:
            logging.info("Training new XSS model...")
            model, scaler = train_xss_model()

        # Run checks
        regex_result = check_xss_regex(input_string)
        ml_result = predict_xss(input_string, model, scaler)
        vulnerability = "XSS" if "XSS Detected" in regex_result or "XSS Detected" in ml_result else "Safe"

        # Generate report
        report = {
            'input': input_string,
            'regex_result': regex_result,
            'ml_result': ml_result,
            'final_result': vulnerability,
            'report': (
                f"MShield XSS Report\n"
                f"Input: {input_string}\n"
                f"Regex: {regex_result}\n"
                f"ML: {ml_result}\n"
                f"Impact: Potential client-side code execution (e.g., cookie theft).\n"
                f"PoC: If XSS, try injecting in a form or URL parameter.\n"
                f"Recommendation: Sanitize input, use Content Security Policy (CSP)."
            )
        }
        return report
    except Exception as e:
        logging.error(f"Error processing input: {str(e)}")
        return {'error': f"Processing failed: {str(e)}"}

def save_results(results, json_file, csv_file):
    """Save results to JSON and CSV."""
    # JSON
    with open(json_file, 'w') as f:
        json.dump(results, f, indent=4)
    
    # CSV
    with open(csv_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['input', 'regex_result', 'ml_result', 'final_result'])
        writer.writeheader()
        writer.writerow({
            'input': results['input'],
            'regex_result': results['regex_result'],
            'ml_result': results['ml_result'],
            'final_result': results['final_result']
        })
    logging.info(f"Results saved to {json_file} and {csv_file}")

def main():
    """Command-line interface for MShield XSS Checker."""
    parser = argparse.ArgumentParser(description="MShield: XSS Vulnerability Checker")
    parser.add_argument('--input', type=str, required=True, help="Input string to check for XSS")
    parser.add_argument('--json-output', type=str, default='mshield_report.json', help="Output JSON file")
    parser.add_argument('--csv-output', type=str, default='mshield_report.csv', help="Output CSV file")
    args = parser.parse_args()

    result = mshield_xss_check(args.input)
    if 'error' not in result:
        save_results(result, args.json_output, args.csv_output)
    
    # Print result
    print(f"\nInput: {result.get('input', 'N/A')}")
    print(f"Regex Result: {result.get('regex_result', 'N/A')}")
    print(f"ML Result: {result.get('ml_result', 'N/A')}")
    print(f"Final Result: {result.get('final_result', 'Error')}")
    print(f"Report:\n{result.get('report', 'Error occurred.')}")
    if 'error' not in result:
        print(f"\nResults saved to {args.json_output} and {args.csv_output}")

if __name__ == "__main__":
    # Local test inputs (simulating TryHackMe)
    test_inputs = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<input onfocus=alert(1)>",
        "vbscript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "Hello world",
        "<p>Safe text</p>",
        "Search query",
        "<div>Content</div>",
    ]
    
    # Run local tests
    for inp in test_inputs:
        result = mshield_xss_check(inp)
        print(f"\nInput: {result.get('input', 'N/A')}")
        print(f"Regex Result: {result.get('regex_result', 'N/A')}")
        print(f"ML Result: {result.get('ml_result', 'N/A')}")
        print(f"Final Result: {result.get('final_result', 'Error')}")
        print(f"Report:\n{result.get('report', 'Error occurred.')}")