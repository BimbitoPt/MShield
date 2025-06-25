import pandas as pd
import re
import logging
import os
import csv
import urllib.parse
import base64
from typing import List, Dict, Any
from functools import lru_cache

# Ensure directories exist
os.makedirs('mshield/logs', exist_ok=True)
os.makedirs('data', exist_ok=True)

# Configure logging
logging.basicConfig(
    filename='mshield/logs/xss_checker_v3.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Precompiled regex patterns
SVG_PATTERN = re.compile(r'<svg\b[^>]*>', re.IGNORECASE)
IMG_PATTERN = re.compile(r'<img\s+[^>]*?(onerror|onmousemove|src\s*=\s*[\'"]?[^\'">]+[\'"]?)', re.IGNORECASE)
SCRIPT_PATTERN = re.compile(
    r'<sc?r?i?p?t\b[^>]*>|eval\s*\(|decodeURIComponent\s*\(|atob\s*\(|String\.fromCharCode\s*\(',
    re.IGNORECASE
)
EVENT_PATTERN = re.compile(
    r'\b(on(focus|mouseover|mousemove|load|error|click|scroll|pointerdown|pointermove|pointerrawupdate|'
    r'mouse(enter|leave|down|up|move)|key(down|up|press)|touch(start|end|move|cancel)|'
    r'drag(start|end|over|drop)|wheel|input|change|submit))\s*=\s*[\'"]?[^\'">]+[\'"]?',
    re.IGNORECASE
)
IFRAME_A_EMBED_PATTERN = re.compile(
    r'<(iframe|embed|object)\s+[^>]*?src\s*=\s*[\'"]?(javascript|data|vbscript):[^>]+[\'"]?>|'
    r'<a\s+[^>]*?href\s*=\s*[\'"]?(javascript|data|vbscript):[^\'">]+[\'"]?',
    re.IGNORECASE
)
BODY_PATTERN = re.compile(
    r'<body\s+[^>]*?on(load|error)\s*=\s*[\'"]?[^\'">]+[\'"]?>',
    re.IGNORECASE
)
MALFORMED_QUOTES_PATTERN = re.compile(r'"+\s*$')
BASE64_PATTERN = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
SANITIZATION_RISK_PATTERN = re.compile(
    r'<sc?r?i?p?t\b[^>]*>|on(scroll|load)\s*=|eval\s*\(',
    re.IGNORECASE
)
LOW_RISK_EVENT_PATTERN = re.compile(
    r'\b(on(error|focus))\s*=\s*[\',String.join(]+[\'"]?',
    re.IGNORECASE
)

@lru_cache(maxsize=1024)
def decode_payload(payload: str) -> str:
    """Decode URL-encoded or base64-encoded payloads efficiently."""
    try:
        decoded = urllib.parse.unquote(payload)
        if BASE64_PATTERN.match(decoded):
            try:
                decoded = base64.b64decode(decoded).decode('utf-8', errors='ignore')
            except (base64.binascii.Error, UnicodeDecodeError):
                pass
        return decoded
    except Exception as e:
        logger.warning(f"Failed to decode payload {payload}: {e}")
        return payload

def normalize_payload(payload: str) -> str:
    """Normalize payload by removing extra spaces and standardizing quotes."""
    try:
        normalized = re.sub(r'\s+', ' ', payload.strip())
        normalized = re.sub(r'[\'"]{2,}', '"', normalized)
        return normalized
    except Exception as e:
        logger.warning(f"Failed to normalize payload {payload}: {e}")
        return payload

def analyze_context(payload: str, input_field: str = "unknown") -> str:
    """Analyze payload context and triggering likelihood based on input field."""
    try:
        decoded = decode_payload(payload)
        normalized = normalize_payload(decoded)
        
        # Field-specific sanitization checks
        if input_field == "search_bar" and (SANITIZATION_RISK_PATTERN.search(normalized) or EVENT_PATTERN.search(normalized)):
            return "Low likelihood in search bar (strict sanitization)"
        if 'vbscript:' in normalized:
            return "Low likelihood (vbscript not supported in modern browsers)"
        if MALFORMED_QUOTES_PATTERN.search(normalized):
            return "Low likelihood in search bar (malformed syntax)"
        if 'data:' in normalized:
            return "Moderate likelihood in product reviews or profile bio (data URL)"
        if BODY_PATTERN.search(normalized):
            return "High likelihood in profile bio (body event)"
        if LOW_RISK_EVENT_PATTERN.search(normalized):
            return "High likelihood in product reviews or profile bio (e.g., onerror, focus)"
        if EVENT_PATTERN.search(normalized):
            return "Moderate likelihood in product reviews or profile bio (e.g., mouseover, click)"
        if IFRAME_A_EMBED_PATTERN.search(normalized) and 'javascript:' in normalized:
            return "High likelihood in product reviews or profile bio (javascript URL)"
        if IFRAME_A_EMBED_PATTERN.search(normalized):
            return "Moderate likelihood in product reviews or profile bio (data/vbscript URL)"
        return f"Moderate likelihood, test in product reviews or profile bio (input: {input_field})"
    except Exception as e:
        logger.warning(f"Context analysis failed for {payload}: {e}")
        return "Unknown context"

def detect_features(payload: str, input_field: str = "unknown") -> Dict[str, Any]:
    """Detect XSS features and context in a payload."""
    try:
        decoded = decode_payload(payload)
        normalized = normalize_payload(decoded)
        if MALFORMED_QUOTES_PATTERN.search(payload):
            logger.warning(f"Malformed payload detected: {payload}")

        features = {
            'svg_count': len(SVG_PATTERN.findall(normalized)),
            'img_detected': bool(IMG_PATTERN.search(normalized)),
            'script_detected': bool(SCRIPT_PATTERN.search(normalized)),
            'event_detected': bool(EVENT_PATTERN.search(normalized)),
            'iframe_a_detected': bool(IFRAME_A_EMBED_PATTERN.search(normalized)),
            'body_detected': bool(BODY_PATTERN.search(normalized)),
            'context': analyze_context(payload, input_field)
        }
        features['is_xss'] = any([
            features['svg_count'] > 0,
            features['img_detected'],
            features['script_detected'],
            features['event_detected'],
            features['iframe_a_detected'],
            features['body_detected']
        ])
        
        if features['is_xss'] and features['context'].startswith('Low likelihood'):
            logger.warning(f"Payload {payload} may fail in {input_field} due to sanitization")
        elif features['is_xss'] and features['context'].startswith('High likelihood'):
            logger.info(f"Payload {payload} likely to trigger in {input_field}")
        
        return features
    except Exception as e:
        logger.error(f"Error detecting features for {payload}: {e}")
        return {
            'svg_count': 0,
            'img_detected': False,
            'script_detected': False,
            'event_detected': False,
            'iframe_a_detected': False,
            'body_detected': False,
            'context': f"Error in analysis: {str(e)}",
            'is_xss': False
        }

def process_payloads(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Process payloads and generate results with failure and success logging."""
    results = []
    failed_payloads = []
    working_payloads = []
    
    input_fields = ['search_bar', 'product_reviews', 'profile_bio']  # Rotate through fields
    
    for _, row in df.iterrows():
        payload = str(row['payload'])
        input_field = row.get('input_field', 'unknown') if 'input_field' in df.columns else input_fields[0]
        features = detect_features(payload, input_field)
        is_xss = features['is_xss']
        expected = str(row.get('is_malicious', 'False')).lower() == 'true'
        
        if pd.isna(row.get('is_malicious')):
            logger.warning(f"Missing is_malicious for payload: {payload}, defaulting to False")
        
        result = {
            'payload': payload,
            'input_field': input_field,
            'is_xss': is_xss,
            'svg_count': features['svg_count'],
            'img_detected': bool(features['img_detected']),
            'script_detected': bool(features['script_detected']),
            'event_detected': bool(features['event_detected']),
            'iframe_a_embed_detected': bool(features['iframe_a_detected']),
            'body_detected': bool(features['body_detected']),
            'context': features['context'],
            'expected': expected
        }
        results.append(result)
        
        if is_xss and expected:
            if features['context'].startswith('Low likelihood'):
                failed_payloads.append(f"{payload} | Alert expected | No alert | {features['context']} | {input_field}")
            elif features['context'].startswith(('High likelihood', 'Moderate likelihood')):
                working_payloads.append(f"{payload} | Alert expected | Alert triggered | {features['context']} | {input_field}")
        
        logger.info(f"Checked {payload} in {input_field}: XSS={'Yes' if is_xss else 'No'}, Expected={expected}, Context={features['context']}")
    
    # Write failed payloads
    if failed_payloads:
        with open('data/mshield_failed_xss.txt', 'w', encoding='utf-8') as f:
            f.write(f"# Failed XSS Payloads - {pd.Timestamp.now()}\n")
            f.write("# Payload | Expected Behavior | Actual Behavior | Failure Reason | Test Context\n")
            f.write('\n'.join(failed_payloads) + '\n')
        logger.info("Failed payloads saved to mshield/data/mshield_failed_xss.txt")
    
    # Write working payloads
    if working_payloads:
        with open('data/mshield_working_xss.txt', 'w', encoding='utf-8') as f:
            f.write(f"# Working XSS Payloads - {pd.Timestamp.now()}\n")
            f.write("# Payload | Expected Behavior | Actual Behavior | Context | Test Context\n")
            f.write('\n'.join(working_payloads) + '\n')
        logger.info("Working payloads saved to mshield/data/mshield_working_xss.txt")
    
    return results

def main():
    """Main function to process XSS payloads."""
    try:
        df = pd.read_csv(
            'data/mshield_xss_data.csv',
            quoting=csv.QUOTE_ALL,
            dtype={'payload': str, 'source': str, 'is_malicious': str, 'notes': str, 'input_field': str},
            keep_default_na=False,
            escapechar='\\'
        )
        
        results = process_payloads(df)
        
        pd.DataFrame(results).to_csv('data/xss_results.csv', index=False, quoting=csv.QUOTE_ALL)
        logger.info("Results saved to data/xss_results.csv")
        
        correct = sum(1 for result in results if str(result['is_xss']).lower() == str(result['expected']).lower())
        accuracy = (correct / len(results)) * 100 if results else 0
        logger.info(f"Detection accuracy: {accuracy:.2f}% ({correct}/{len(results)})")
        
    except Exception as e:
        logger.error(f"Main error: {e}")
        raise

if __name__ == "__main__":
    main()