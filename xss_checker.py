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
INPUT_PATTERN = re.compile(r'<input\s+[^>]*?(onfocus|autofocus)', re.IGNORECASE)
VIDEO_PATTERN = re.compile(r'<video\s+[^>]*?(onerror|src\s*=\s*[\'"]?[^\'">]+[\'"]?)', re.IGNORECASE)
AUDIO_PATTERN = re.compile(r'<audio\s+[^>]*?(onerror|src\s*=\s*[\'"]?[^\'">]+[\'"]?)', re.IGNORECASE)
BUTTON_PATTERN = re.compile(r'<button\s+[^>]*?onclick', re.IGNORECASE)
DETAILS_PATTERN = re.compile(r'<details\s+[^>]*?ontoggle', re.IGNORECASE)
TEXTAREA_PATTERN = re.compile(r'<textarea\s+[^>]*?(onfocus|autofocus)', re.IGNORECASE)
FORM_PATTERN = re.compile(r'<form\s+[^>]*?onsubmit', re.IGNORECASE)
SELECT_PATTERN = re.compile(r'<select\s+[^>]*?onchange', re.IGNORECASE)
SCRIPT_PATTERN = re.compile(r'<sc?r?i?p?t\b[^>]*>.*?</script>', re.IGNORECASE)
JAVASCRIPT_URL_PATTERN = re.compile(r'javascript:[^\'">]+', re.IGNORECASE)
ENCODED_TAG_PATTERN = re.compile(r'%3C|<[^>]+>|&#x?[<]', re.IGNORECASE)
EVENT_PATTERN = re.compile(
    r'\b(on(focus|mouseover|mousemove|load|error|click|scroll|pointerdown|pointermove|pointerrawupdate|'
    r'mouse(enter|leave|down|up|move)|key(down|up|press)|touch(start|end|move|cancel)|'
    r'drag(start|end|over|drop)|wheel|input|change|submit|toggle))\s*=\s*[\'"]?[^\'">]+[\'"]?',
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
DOM_XSS_PATTERN = re.compile(
    r'(javascript|data):[^\'">]+|[\'"]\s*(on\w+|alert\(|console\.log\(|prompt\()',
    re.IGNORECASE
)
POLYGLOT_PATTERN = re.compile(
    r'(<script>.*?</script>.*?<[^>]+on\w+=)|(<[^>]+on\w+=.*?[<script>])',
    re.IGNORECASE
)
ENCODED_PATTERN = re.compile(
    r'%[0-9A-Fa-f]{2}|%u[0-9A-Fa-f]{4}|&#x?[0-9A-Fa-f]+;|[\\x][0-9A-Fa-f]{2}',
    re.IGNORECASE
)
MALFORMED_QUOTES_PATTERN = re.compile(r'"+\s*$')
BASE64_PATTERN = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')
SANITIZATION_RISK_PATTERN = re.compile(
    r'<sc?r?i?p?t\b[^>]*>|eval\s*\(',
    re.IGNORECASE
)

# Known results for Juice Shop search bar
KNOWN_RESULTS = {
    '<img src=x onerror=alert(1)>': ('working', 'High likelihood in search bar (img with onerror)', 'Alert triggered'),
    '<input onfocus=alert(1) autofocus>': ('working', 'High likelihood in search bar (input with onfocus)', 'Alert triggered'),
    '<video src=x onerror=alert(1)>': ('working', 'High likelihood in search bar (video with onerror)', 'Alert triggered'),
    '<audio src=x onerror=alert(1)>': ('working', 'High likelihood in search bar (audio with onerror)', 'Alert triggered'),
    '<details open ontoggle=alert(1)>': ('working', 'High likelihood in search bar (details with ontoggle)', 'Alert triggered'),
    '<textarea onfocus=alert(1) autofocus>': ('working', 'High likelihood in search bar (textarea with onfocus)', 'Alert triggered'),
    '<button onclick=alert(1)>Click</button>': ('working', 'High likelihood in search bar (button with onclick)', 'Alert triggered'),
    '<img src=invalid onerror=alert(1)>': ('working', 'High likelihood in search bar (img with onerror)', 'Alert triggered'),
    '"><img src=x onerror=alert(1)>': ('working', 'High likelihood in search bar (img with onerror)', 'Alert triggered'),
    '<form onsubmit=alert(1)><input type=submit>': ('failed', 'Low likelihood in search bar (sanitized form onsubmit)', 'No alert'),
    '" onmouseover=alert(1)': ('failed', 'Low likelihood in search bar (sanitized onmouseover)', 'No alert'),
    'javascript:alert(1)': ('failed', 'Low likelihood in search bar (sanitized javascript URL)', 'No alert')
}

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

def analyze_context(payload: str, input_field: str = "unknown", sanitization_level: str = "medium") -> str:
    """Analyze payload context and triggering likelihood based on input field and sanitization level."""
    try:
        # Check known results for Juice Shop first
        if payload in KNOWN_RESULTS and input_field == "search_bar":
            return KNOWN_RESULTS[payload][1]
        
        decoded = decode_payload(payload)
        normalized = normalize_payload(decoded)
        
        # Adjust likelihood based on sanitization level
        if sanitization_level == "low":
            if SCRIPT_PATTERN.search(normalized) or JAVASCRIPT_URL_PATTERN.search(normalized):
                return f"High likelihood in {input_field} (low sanitization allows scripts/URLs)"
            if EVENT_PATTERN.search(normalized):
                return f"High likelihood in {input_field} (low sanitization allows events)"
        elif sanitization_level == "high":
            if ENCODED_TAG_PATTERN.search(normalized) and not any(x in decoded.lower() for x in ['<script', '<img', '<input']):
                return f"Moderate likelihood in {input_field} (high sanitization may allow encoded tags)"
            if DOM_XSS_PATTERN.search(normalized) and 'javascript:' in normalized.lower():
                return f"Moderate likelihood in {input_field} (possible DOM-based XSS)"
            if EVENT_PATTERN.search(normalized):
                return f"Low likelihood in {input_field} (high sanitization blocks events)"
        
        # Default analysis (medium sanitization, e.g., Juice Shop search bar)
        if input_field == "search_bar":
            if IMG_PATTERN.search(normalized) and 'onerror' in normalized.lower():
                return "High likelihood in search bar (img with onerror)"
            if INPUT_PATTERN.search(normalized) and 'onfocus' in normalized.lower():
                return "High likelihood in search bar (input with onfocus)"
            if VIDEO_PATTERN.search(normalized) and 'onerror' in normalized.lower():
                return "High likelihood in search bar (video with onerror)"
            if AUDIO_PATTERN.search(normalized) and 'onerror' in normalized.lower():
                return "High likelihood in search bar (audio with onerror)"
            if BUTTON_PATTERN.search(normalized) and 'onclick' in normalized.lower():
                return "High likelihood in search bar (button with onclick)"
            if DETAILS_PATTERN.search(normalized) and 'ontoggle' in normalized.lower():
                return "High likelihood in search bar (details with ontoggle)"
            if TEXTAREA_PATTERN.search(normalized) and 'onfocus' in normalized.lower():
                return "High likelihood in search bar (textarea with onfocus)"
            if SELECT_PATTERN.search(normalized) and 'onchange' in normalized.lower():
                return "High likelihood in search bar (select with onchange)"
            if FORM_PATTERN.search(normalized) and 'onsubmit' in normalized.lower():
                return "Low likelihood in search bar (sanitized form onsubmit)"
            if EVENT_PATTERN.search(normalized) and 'onmouseover' in normalized.lower():
                return "Low likelihood in search bar (sanitized onmouseover)"
            if JAVASCRIPT_URL_PATTERN.search(normalized):
                return "Low likelihood in search bar (sanitized javascript URL)"
            if SANITIZATION_RISK_PATTERN.search(normalized) or BODY_PATTERN.search(normalized):
                return "Low likelihood in search bar (strict sanitization)"
            if ENCODED_PATTERN.search(normalized) and '<script' in decoded.lower():
                return "Low likelihood in search bar (script with encoding)"
            if POLYGLOT_PATTERN.search(normalized) or DOM_XSS_PATTERN.search(normalized):
                return "Moderate likelihood in search bar (possible DOM-based XSS or polyglot)"
        
        # Other input fields (e.g., profile bio, comments)
        if input_field in ["profile_bio", "comments"]:
            if SCRIPT_PATTERN.search(normalized):
                return f"Moderate likelihood in {input_field} (scripts may be allowed)"
            if EVENT_PATTERN.search(normalized):
                return f"High likelihood in {input_field} (events often allowed)"
            if ENCODED_TAG_PATTERN.search(normalized):
                return f"Moderate likelihood in {input_field} (encoded tags may bypass)"
        
        if 'vbscript:' in normalized:
            return "Low likelihood (vbscript not supported)"
        if MALFORMED_QUOTES_PATTERN.search(normalized):
            return f"Low likelihood in {input_field} (malformed syntax)"
        if 'data:' in normalized:
            return f"Moderate likelihood in {input_field} (data URL)"
        if BODY_PATTERN.search(normalized):
            return f"High likelihood in {input_field} (body event)"
        if IFRAME_A_EMBED_PATTERN.search(normalized) and 'javascript:' in normalized:
            return f"High likelihood in {input_field} (javascript URL)"
        if IFRAME_A_EMBED_PATTERN.search(normalized):
            return f"Moderate likelihood in {input_field} (data/vbscript URL)"
        return f"Moderate likelihood, test in {input_field} (unknown context)"
    except Exception as e:
        logger.warning(f"Context analysis failed for {payload}: {e}")
        return "Unknown context"

def detect_features(payload: str, input_field: str = "unknown", sanitization_level: str = "medium") -> Dict[str, Any]:
    """Detect XSS features and context in a payload."""
    try:
        decoded = decode_payload(payload)
        normalized = normalize_payload(decoded)
        if MALFORMED_QUOTES_PATTERN.search(payload):
            logger.warning(f"Malformed payload detected: {payload}")

        features = {
            'svg_count': len(SVG_PATTERN.findall(normalized)),
            'img_detected': bool(IMG_PATTERN.search(normalized)),
            'input_detected': bool(INPUT_PATTERN.search(normalized)),
            'video_detected': bool(VIDEO_PATTERN.search(normalized)),
            'audio_detected': bool(AUDIO_PATTERN.search(normalized)),
            'button_detected': bool(BUTTON_PATTERN.search(normalized)),
            'details_detected': bool(DETAILS_PATTERN.search(normalized)),
            'textarea_detected': bool(TEXTAREA_PATTERN.search(normalized)),
            'form_detected': bool(FORM_PATTERN.search(normalized)),
            'select_detected': bool(SELECT_PATTERN.search(normalized)),
            'script_detected': bool(SCRIPT_PATTERN.search(normalized)),
            'javascript_url_detected': bool(JAVASCRIPT_URL_PATTERN.search(normalized)),
            'encoded_tag_detected': bool(ENCODED_TAG_PATTERN.search(normalized)),
            'event_detected': bool(EVENT_PATTERN.search(normalized)),
            'iframe_a_detected': bool(IFRAME_A_EMBED_PATTERN.search(normalized)),
            'body_detected': bool(BODY_PATTERN.search(normalized)),
            'dom_xss_detected': bool(DOM_XSS_PATTERN.search(normalized)),
            'polyglot_detected': bool(POLYGLOT_PATTERN.search(normalized)),
            'encoded_detected': bool(ENCODED_PATTERN.search(normalized)),
            'context': analyze_context(payload, input_field, sanitization_level)
        }
        features['is_xss'] = any([
            features['svg_count'] > 0,
            features['img_detected'],
            features['input_detected'],
            features['video_detected'],
            features['audio_detected'],
            features['button_detected'],
            features['details_detected'],
            features['textarea_detected'],
            features['form_detected'],
            features['select_detected'],
            features['script_detected'],
            features['javascript_url_detected'],
            features['encoded_tag_detected'],
            features['event_detected'],
            features['iframe_a_detected'],
            features['body_detected'],
            features['dom_xss_detected'],
            features['polyglot_detected'],
            features['encoded_detected']
        ])
        
        if features['is_xss'] and features['context'].startswith('Low likelihood'):
            logger.warning(f"Payload {payload} may fail in {input_field} due to sanitization")
        elif features['is_xss'] and features['context'].startswith(('High likelihood', 'Moderate likelihood')):
            logger.info(f"Payload {payload} may trigger in {input_field}, requires manual testing")
        
        return features
    except Exception as e:
        logger.error(f"Error detecting features for {payload}: {e}")
        return {
            'svg_count': 0,
            'img_detected': False,
            'input_detected': False,
            'video_detected': False,
            'audio_detected': False,
            'button_detected': False,
            'details_detected': False,
            'textarea_detected': False,
            'form_detected': False,
            'select_detected': False,
            'script_detected': False,
            'javascript_url_detected': False,
            'encoded_tag_detected': False,
            'event_detected': False,
            'iframe_a_detected': False,
            'body_detected': False,
            'dom_xss_detected': False,
            'polyglot_detected': False,
            'encoded_detected': False,
            'context': f"Error in analysis: {str(e)}",
            'is_xss': False
        }

def process_payloads(df: pd.DataFrame, sanitization_level: str = "medium") -> List[Dict[str, Any]]:
    """Process payloads and generate results with failure and success logging."""
    results = []
    failed_payloads = set()  # Deduplicate logs
    working_payloads = set()  # Deduplicate logs
    
    input_fields = ['search_bar', 'profile_bio', 'comments']  # Support multiple contexts
    for _, row in df.iterrows():
        payload = str(row['payload'])
        input_field = row.get('input_field', input_fields[0]) if 'input_field' in df.columns else input_fields[0]
        features = detect_features(payload, input_field, sanitization_level)
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
            'input_detected': bool(features['input_detected']),
            'video_detected': bool(features['video_detected']),
            'audio_detected': bool(features['audio_detected']),
            'button_detected': bool(features['button_detected']),
            'details_detected': bool(features['details_detected']),
            'textarea_detected': bool(features['textarea_detected']),
            'form_detected': bool(features['form_detected']),
            'select_detected': bool(features['select_detected']),
            'script_detected': bool(features['script_detected']),
            'javascript_url_detected': bool(features['javascript_url_detected']),
            'encoded_tag_detected': bool(features['encoded_tag_detected']),
            'event_detected': bool(features['event_detected']),
            'iframe_a_embed_detected': bool(features['iframe_a_detected']),
            'body_detected': bool(features['body_detected']),
            'dom_xss_detected': bool(features['dom_xss_detected']),
            'polyglot_detected': bool(features['polyglot_detected']),
            'encoded_detected': bool(features['encoded_detected']),
            'context': features['context'],
            'expected': expected
        }
        results.append(result)
        
        # Log based on known results or context
        if is_xss and expected:
            if payload in KNOWN_RESULTS and input_field == "search_bar":
                status, context, actual_behavior = KNOWN_RESULTS[payload]
                log_entry = f"{payload} | Alert expected | {actual_behavior} | {context} | {input_field}"
                if status == 'working':
                    working_payloads.add(log_entry)
                else:
                    failed_payloads.add(log_entry)
            elif features['context'].startswith('Low likelihood'):
                failed_payloads.add(f"{payload} | Alert expected | No alert | {features['context']} | {input_field}")
            else:
                working_payloads.add(f"{payload} | Alert expected | Manual testing required | {features['context']} | {input_field}")
        
        logger.info(f"Checked {payload} in {input_field}: XSS={'Yes' if is_xss else 'No'}, Expected={expected}, Context={features['context']}")
    
    # Write failed payloads
    if failed_payloads:
        with open('data/mshield_failed_xss.txt', 'w', encoding='utf-8') as f:
            f.write(f"# Failed XSS Payloads - {pd.Timestamp.now()}\n")
            f.write("# Payload | Expected Behavior | Actual Behavior | Context | Test Context\n")
            f.write('\n'.join(sorted(failed_payloads)) + '\n')
        logger.info("Failed payloads saved to data/mshield_failed_xss.txt")
    
    # Write working payloads
    if working_payloads:
        with open('data/mshield_working_xss.txt', 'w', encoding='utf-8') as f:
            f.write(f"# Working XSS Payloads - {pd.Timestamp.now()}\n")
            f.write("# Payload | Expected Behavior | Actual Behavior | Context | Test Context\n")
            f.write('\n'.join(sorted(working_payloads)) + '\n')
        logger.info("Working payloads saved to data/mshield_working_xss.txt")
    
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
        
        # Test with medium sanitization for Juice Shop
        results = process_payloads(df, sanitization_level="medium")
        
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