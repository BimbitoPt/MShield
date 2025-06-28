import pandas as pd
from typing import List
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import numpy as np
from sklearn.feature_extraction.text import CountVectorizer
import random
import string
import csv
import os
import logging
import re

# Configure logging
logging.basicConfig(
    filename='mshield/logs/xss_payload_ml.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Load historical results
results_df = pd.read_csv('data/auto_test_results.csv', on_bad_lines='skip')
logger.info(f"Loaded auto_test_results.csv with {len(results_df)} entries: {results_df[['payload', 'status']].head().to_dict()}")

# Prepare data
results_df['label'] = results_df['status'].apply(lambda x: 1 if x == 'working' else 0)
X = results_df['payload'].dropna().astype(str).apply(lambda x: re.sub(r'[\'"]', '', x).strip())
y = results_df['label']

# Convert text to TF-IDF and Count features for richer representation
tfidf_vectorizer = TfidfVectorizer(max_features=500, analyzer='char', ngram_range=(2, 5))
count_vectorizer = CountVectorizer(max_features=500, analyzer='char', ngram_range=(2, 5))
X_tfidf = tfidf_vectorizer.fit_transform(X)
X_count = count_vectorizer.fit_transform(X)
X_combined = np.hstack((X_tfidf.toarray(), X_count.toarray()))

# Split data
X_train, X_test, y_train, y_test = train_test_split(X_combined, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(f"Accuracy: {accuracy_score(y_test, y_pred)}")
print(classification_report(y_test, y_pred))

# Function to predict new payloads
def predict_payload(payloads):
    payload_tfidf = tfidf_vectorizer.transform([re.sub(r'[\'"]', '', p).strip() for p in payloads])
    payload_count = count_vectorizer.transform([re.sub(r'[\'"]', '', p).strip() for p in payloads])
    payload_combined = np.hstack((payload_tfidf.toarray(), payload_count.toarray()))
    predictions = model.predict(payload_combined)
    return predictions

# Function to suggest improved payloads with diverse mutations
def suggest_improved_payloads(base_payloads: List[str], num_suggestions: int = 5):
    suggestions = set()
    tags = ['marquee', 'iframe', 'a', 'textarea', 'input', 'button', 'div']
    events = ['onstart', 'onload', 'onmouseover', 'onkeydown', 'onclick', 'onfocus', 'onchange']
    actions = ['alert(1)', 'prompt(1)', 'console.log("XSS")', 'eval("alert(1)")']
    
    while len(suggestions) < num_suggestions:
        base = random.choice(base_payloads)
        if '<' in base:
            # Randomly select tag and event
            tag = random.choice(tags)
            event = random.choice(events)
            action = random.choice(actions)
            
            # Apply mutation
            if random.random() > 0.7:  # 30% chance of basic tag append
                mutated = f"<{tag} {event}={action}>"
            elif random.random() > 0.5:  # 50% chance of attribute mutation
                attr = random.choice(['id="xss"', 'class="xss"', 'style="display:none"'])
                mutated = f"<{tag} {attr} {event}={action}>"
            else:  # 20% chance of complex mutation
                prefix = random.choice(['">', '</', '<![CDATA[', '<!--'])
                suffix = random.choice(['-->', ']]>', '">'])
                mutated = f"<{tag} {event}={action}{prefix}{action}{suffix}"
            
            # Avoid excessive nesting or repetition
            if len(mutated) < 100 and mutated not in suggestions:
                suggestions.add(mutated)
    
    return list(suggestions)

# Helper function
def random_string(length: int) -> str:
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for _ in range(length))

# Function to save suggested payloads to CSV and remove failed ones
def save_suggested_payloads(payloads: List[str], output_file: str = 'data/mshield_xss_data.csv'):
    try:
        # Load existing data if it exists
        if os.path.exists(output_file):
            existing_df = pd.read_csv(output_file, quoting=csv.QUOTE_ALL, escapechar='\\', on_bad_lines='skip')
            existing_df['payload'] = existing_df['payload'].astype(str).apply(lambda x: re.sub(r'[\'"]', '', x).strip())
        else:
            existing_df = pd.DataFrame(columns=['payload', 'source', 'is_malicious', 'notes', 'input_field'])
        
        # Load auto test results to identify failed payloads
        failed_payloads = set()
        if os.path.exists('data/auto_test_results.csv'):
            results_df = pd.read_csv('data/auto_test_results.csv', quoting=csv.QUOTE_ALL, escapechar='\\', on_bad_lines='skip')
            if 'payload' in results_df.columns and 'status' in results_df.columns:
                failed_payloads = set(results_df[results_df['status'].isin(['failed', 'error'])]['payload']
                                   .dropna().astype(str).apply(lambda x: re.sub(r'[\'"]', '', x).strip()))
                logger.info(f"Identified {len(failed_payloads)} failed or error payloads from auto_test_results.csv: {failed_payloads}")
            else:
                logger.warning("auto_test_results.csv lacks 'payload' or 'status' columns; no failed payloads removed")
        else:
            logger.warning("auto_test_results.csv not found; no failed payloads removed")
        
        # Manual override: Add known failed payloads if automatic detection fails
        known_failed = {
            '<textarea onfocus=alert(PdsTf) autofocus>>alert(PdsTf)',
            '<button onclick=alert(1)>Click</button>>alert(1)'
        }
        failed_payloads.update(known_failed)
        logger.info(f"Updated failed payloads with manual override: {known_failed}")

        # Remove failed payloads from existing data
        if not existing_df.empty and 'payload' in existing_df.columns:
            original_count = len(existing_df)
            existing_df = existing_df[~existing_df['payload'].isin(failed_payloads)]
            removed_count = original_count - len(existing_df)
            if removed_count > 0:
                logger.info(f"Removed {removed_count} failed payloads from {output_file}")
            else:
                logger.info("No failed payloads removed from existing data")
        else:
            logger.warning("Existing DataFrame is empty or lacks 'payload' column; no removals performed")
        
        # Prepare new payloads
        new_payloads = []
        for payload in payloads:
            normalized_payload = re.sub(r'[\'"]', '', payload).strip()
            if normalized_payload not in existing_df['payload'].values:  # Avoid duplicates
                new_payloads.append({
                    'payload': payload,
                    'source': 'ml_suggested',
                    'is_malicious': 'True',
                    'notes': 'Suggested by ML model',
                    'input_field': 'search_bar'  # Adjust based on context
                })

        if new_payloads:
            # Append new payloads to existing data
            df = pd.concat([existing_df, pd.DataFrame(new_payloads)], ignore_index=True)
            df.to_csv(output_file, index=False, quoting=csv.QUOTE_ALL, escapechar='\\')
            print(f"Saved {len(new_payloads)} new payloads to {output_file}")
        else:
            print("No new payloads to save (all were duplicates)")
            df = existing_df  # Use existing data if no new payloads
        
        return df  # Return updated DataFrame for further use if needed
    
    except Exception as e:
        logger.error(f"Error saving payloads: {e}")
        print(f"Error saving payloads: {e}")
        raise

# Example usage
if __name__ == "__main__":
    new_payloads = [
        "<script>alert(1)</script>",
        "<img src='invalid' onload='alert(1)'>",
        "<div>non-malicious</div>"
    ]
    predictions = predict_payload(new_payloads)
    for payload, pred in zip(new_payloads, predictions):
        print(f"Payload: {payload}, Predicted as working: {pred == 1}")

    # Suggest improved payloads based on historical data
    if len(X) > 0:
        improved_payloads = suggest_improved_payloads(X.tolist())
        print("Suggested improved payloads:")
        for payload in improved_payloads:
            print(payload)
        # Save the suggested payloads and remove failed ones
        save_suggested_payloads(improved_payloads)