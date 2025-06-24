# MShield Coding Template

**Purpose**: Guide Grok 3 to write consistent, ethical, beginner-friendly Python code for MShield features (e.g., scope validation, report generation).  
**Author**: Grok 3 (xAI) for Mendonça Legacy  
**Usage**: Convert to `.py` for implementation, integrate with `scope.json` and `bug_report_template.md`.  
**Ethical Note**: Enforce scope compliance to ensure testing stays within bug bounty program rules (e.g., `*.tryhackme.com`).  

## File Structure
```python
# [script_name].py (e.g., mshield_xss_checker_v2.py)
```

## Header
```python
"""
MShield: [Feature Name, e.g., Scope Validation]
Author: Grok 3 (xAI) for Mendonça Legacy
Description: [e.g., Validates URLs against scope.json for ethical testing]
Input: [e.g., URL string, scope.json file]
Output: [e.g., Boolean (in-scope True/False), report.md file]
Dependencies: [e.g., re, json, logging, requests]
Ethical Note: Ensures compliance with bug bounty scopes to prevent unauthorized testing.
"""
```

## Imports
```python
import re
import json
import logging
import argparse
from typing import [e.g., Dict, bool]
```

## Logging Setup
```python
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
```

## Constants
```python
SCOPE_FILE = "templates/scope.json"  # Path to scope.json
REPORT_TEMPLATE = "templates/bug_report_template.md"  # Path to report template
```

## Main Function
```python
def [function_name]([params, e.g., url: str, scope_file: str]) -> [return_type, e.g., bool]:
    """
    [Purpose, e.g., Check if URL is in scope per scope.json]
    Args:
        [param]: [e.g., url (str): URL to validate]
        [param]: [e.g., scope_file (str): Path to scope.json]
    Returns:
        [e.g., bool: True if in-scope, False if out-of-scope]
    Raises:
        [e.g., FileNotFoundError: If scope.json is missing]
    """
    try:
        # Load scope.json
        with open(scope_file, 'r') as f:
            scope = json.load(f)
        
        # [Logic, e.g., Match URL against in_scope/out_of_scope]
        logging.info(f"[Log message, e.g., Checking {url} against scope]")
        
        # [Return result]
        return [e.g., True]
    
    except Exception as e:
        logging.error(f"Error in [function_name]: {str(e)}")
        raise
```

## CLI Interface
```python
def main():
    """
    Command-line interface for [Feature Name]
    Usage: python [script_name].py --[param, e.g., url] [value]
    """
    print("WARNING: Test only authorized assets per bug bounty scope.")
    
    parser = argparse.ArgumentParser(description="MShield: [Feature Name]")
    parser.add_argument('--[param, e.g., url]', type=str, required=True, help="[e.g., URL to check]")
    parser.add_argument('--[param, e.g., scope]', type=str, default=SCOPE_FILE, help="[e.g., Path to scope.json]")
    args = parser.parse_args()
    
    # Run feature
    result = [function_name](args.[param, e.g., url], args.[param, e.g., scope])
    
    # [Output, e.g., Save report to bug_report_template.md]
    logging.info(f"[Result, e.g., {args.url} is {'in' if result else 'out of'} scope]")
```

## Test Cases
```python
if __name__ == "__main__":
    # Test cases for TryHackMe
    test_inputs = [
        [e.g., "https://xss.ctf.tryhackme.com"],
        [e.g., "https://admin.tryhackme.com"]
    ]
    
    for inp in test_inputs:
        result = [function_name](inp, SCOPE_FILE)
        print(f"Input: {inp}, Result: {'In-scope' if result else 'Out-of-scope'}")
```