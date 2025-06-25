import pandas as pd
import logging
import os
import random
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

def generate_xss_payloads(num_payloads: int = 10) -> List[Dict[str, str]]:
    """Generate XSS payloads for various vectors."""
    try:
        # Payload components
        tags = ['img', 'svg', 'input', 'div', 'body', 'a', 'iframe']
        events = ['onerror', 'onload', 'onfocus', 'onmouseover', 'onclick', 'onmousemove']
        schemes = ['javascript:', 'data:']
        actions = ["alert('xss')", "console.log('xss')", "prompt('xss')"]
        input_fields = ['search_bar', 'product_reviews', 'profile_bio']
        
        payloads = []
        
        for _ in range(num_payloads):
            tag = random.choice(tags)
            notes = f"{tag} based"
            input_field = random.choice(input_fields)
            
            if tag in ['img', 'svg', 'div', 'body']:
                event = random.choice(events)
                action = random.choice(actions)
                payload = f'<{tag} {event}="{action}">'
                notes += f" with {event}"
                input_field = 'product_reviews' if event == 'onmouseover' else 'profile_bio' if tag == 'body' else input_field
            elif tag == 'input':
                event = random.choice(events)
                action = random.choice(actions)
                payload = f'<input type="text" {event}="{action}" autofocus>'
                notes += f" with {event}"
                input_field = 'product_reviews'
            elif tag == 'a':
                scheme = random.choice(schemes)
                action = random.choice(actions)
                payload = f'<a href="{scheme}{action}">Click</a>'
                notes += f" with {scheme}"
                input_field = 'product_reviews'
            elif tag == 'iframe':
                scheme = random.choice(schemes)
                action = random.choice(actions)
                payload = f'<iframe src="{scheme}{action}"></iframe>'
                notes += f" with {scheme}"
                input_field = 'profile_bio'
            
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
        
        logger.info(f"Generated {len(payloads)} payloads")
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
        payloads = generate_xss_payloads(num_payloads=10)
        save_payloads(payloads)
    except Exception as e:
        logger.error(f"Main error: {e}")
        raise

if __name__ == "__main__":
    main()