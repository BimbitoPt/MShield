import pandas as pd
import logging
import os
import time
import csv
from typing import List, Dict
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException

# Ensure directories exist
os.makedirs('mshield/logs', exist_ok=True)
os.makedirs('data', exist_ok=True)

# Configure logging
logging.basicConfig(
    filename='mshield/logs/auto_tester.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class XSSAutoTester:
    """Automate XSS payload testing in a web application."""
    
    def __init__(self, url: str, input_selector: str, submit_selector: str = None):
        """Initialize tester with target URL and input field selector."""
        self.url = url
        self.input_selector = input_selector
        self.submit_selector = submit_selector
        self.driver = None
        
    def setup_driver(self):
        """Set up Chrome WebDriver with headless mode."""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--no-sandbox')
            self.driver = webdriver.Chrome(options=chrome_options)
            logger.info("WebDriver initialized")
        except Exception as e:
            logger.error(f"Failed to initialize WebDriver: {e}")
            raise
    
    def teardown_driver(self):
        """Close WebDriver."""
        if self.driver:
            self.driver.quit()
            logger.info("WebDriver closed")
    
    def test_payload(self, payload: str, input_field: str) -> Dict[str, str]:
        """Test a single payload and return result."""
        try:
            self.driver.get(self.url)
            WebDriverWait(self.driver, 5).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, self.input_selector))
            )
            
            # Inject payload
            input_element = self.driver.find_element(By.CSS_SELECTOR, self.input_selector)
            input_element.clear()
            input_element.send_keys(payload)
            
            # Submit form (if submit button exists)
            if self.submit_selector:
                submit_button = self.driver.find_element(By.CSS_SELECTOR, self.submit_selector)
                submit_button.click()
            else:
                input_element.send_keys(Keys.ENTER)
            
            # Check for alert
            try:
                WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                alert = self.driver.switch_to.alert
                alert.accept()
                result = {
                    'payload': payload,
                    'input_field': input_field,
                    'status': 'working',
                    'behavior': 'Alert triggered',
                    'context': f"Successful XSS in {input_field}"
                }
                logger.info(f"Payload {payload} triggered alert in {input_field}")
            except TimeoutException:
                result = {
                    'payload': payload,
                    'input_field': input_field,
                    'status': 'failed',
                    'behavior': 'No alert',
                    'context': f"No XSS detected in {input_field}"
                }
                logger.info(f"Payload {payload} did not trigger alert in {input_field}")
            
            return result
        
        except Exception as e:
            logger.error(f"Error testing payload {payload}: {e}")
            return {
                'payload': payload,
                'input_field': input_field,
                'status': 'error',
                'behavior': 'Test failed',
                'context': f"Error: {str(e)}"
            }
    
    def test_payloads(self, payloads: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Test all payloads and return results."""
        results = []
        self.setup_driver()
        
        try:
            for payload_dict in payloads:
                if payload_dict['is_malicious'] == 'True':
                    result = self.test_payload(payload_dict['payload'], payload_dict['input_field'])
                    results.append(result)
                else:
                    logger.info(f"Skipping non-malicious payload: {payload_dict['payload']}")
        finally:
            self.teardown_driver()
        
        return results

def save_results(results: List[Dict[str, str]]):
    """Save test results to CSV and log files."""
    try:
        # Save to CSV
        df = pd.DataFrame(results)
        df.to_csv('data/auto_test_results.csv', index=False, quoting=csv.QUOTE_ALL)
        logger.info("Results saved to data/auto_test_results.csv")
        
        # Save to working/failed logs
        working = [r for r in results if r['status'] == 'working']
        failed = [r for r in results if r['status'] == 'failed']
        
        if working:
            with open('data/mshield_working_xss.txt', 'a', encoding='utf-8') as f:
                f.write(f"# Working XSS Payloads - {pd.Timestamp.now()}\n")
                f.write("# Payload | Expected Behavior | Actual Behavior | Context | Test Context\n")
                for r in working:
                    f.write(f"{r['payload']} | Alert expected | {r['behavior']} | {r['context']} | {r['input_field']}\n")
            logger.info("Working payloads appended to data/mshield_working_xss.txt")
        
        if failed:
            with open('data/mshield_failed_xss.txt', 'a', encoding='utf-8') as f:
                f.write(f"# Failed XSS Payloads - {pd.Timestamp.now()}\n")
                f.write("# Payload | Expected Behavior | Actual Behavior | Context | Test Context\n")
                for r in failed:
                    f.write(f"{r['payload']} | Alert expected | {r['behavior']} | {r['context']} | {r['input_field']}\n")
            logger.info("Failed payloads appended to data/mshield_failed_xss.txt")
        
    except Exception as e:
        logger.error(f"Error saving results: {e}")
        raise

def main():
    """Main function to run automated XSS testing."""
    try:
        # Load payloads
        df = pd.read_csv(
            'data/mshield_xss_data.csv',
            quoting=csv.QUOTE_ALL,
            dtype={'payload': str, 'source': str, 'is_malicious': str, 'notes': str, 'input_field': str},
            keep_default_na=False,
            escapechar='\\'
        )
        payloads = df.to_dict('records')
        
        # Initialize tester for Juice Shop search bar
        tester = XSSAutoTester(
            url='http://localhost:3000/#/search',
            input_selector='input[placeholder="Search..."]',
            submit_selector='button#searchButton'
        )
        
        # Run tests
        results = tester.test_payloads(payloads)
        
        # Save results
        save_results(results)
        
        # Log summary
        working_count = len([r for r in results if r['status'] == 'working'])
        logger.info(f"Tested {len(payloads)} payloads: {working_count} working, {len(results) - working_count} failed/error")
        
    except Exception as e:
        logger.error(f"Main error: {e}")
        raise

if __name__ == "__main__":
    main()