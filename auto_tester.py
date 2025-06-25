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
from selenium.common.exceptions import TimeoutException, NoSuchElementException, WebDriverException

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
    
    def __init__(self, url: str, input_selector: str, submit_selector: str = None, input_field: str = "search_bar"):
        """Initialize tester with target URL, selectors, and input field type."""
        self.url = url
        self.input_selector = input_selector
        self.submit_selector = submit_selector
        self.input_field = input_field
        self.driver = None
        
    def setup_driver(self):
        """Set up Chrome WebDriver with headless mode."""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--window-size=1920,1080')
            self.driver = webdriver.Chrome(options=chrome_options)
            self.driver.set_page_load_timeout(30)
            logger.info("WebDriver initialized")
        except WebDriverException as e:
            logger.error(f"Failed to initialize WebDriver: {e}")
            raise
    
    def teardown_driver(self):
        """Close WebDriver."""
        if self.driver:
            try:
                self.driver.quit()
                logger.info("WebDriver closed")
            except Exception as e:
                logger.warning(f"Error closing WebDriver: {e}")
    
    def test_payload(self, payload: str, input_field: str) -> Dict[str, str]:
        """Test a single payload and return result."""
        try:
            self.driver.get(self.url)
            # Wait for page to load and input to be visible
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, self.input_selector))
            )
            time.sleep(1)  # Allow Angular to stabilize
            
            # Inject payload
            input_element = self.driver.find_element(By.CSS_SELECTOR, self.input_selector)
            input_element.clear()
            input_element.send_keys(payload)
            
            # Handle field-specific submission
            if input_field == "search_bar" and self.submit_selector:
                try:
                    submit_button = self.driver.find_element(By.CSS_SELECTOR, self.submit_selector)
                    submit_button.click()
                except NoSuchElementException:
                    logger.warning(f"Submit button {self.submit_selector} not found; trying Enter key")
                    input_element.send_keys(Keys.ENTER)
            elif input_field == "search_bar":
                input_element.send_keys(Keys.ENTER)
            elif input_field in ["profile_bio", "comments"]:
                # For non-search fields, trigger interaction if needed
                input_element.send_keys(Keys.TAB)  # Move focus to trigger events like onfocus
                time.sleep(0.5)
            
            # Check for alert with retry
            for _ in range(2):  # Retry twice for dynamic alerts
                try:
                    WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()
                    result = {
                        'payload': payload,
                        'input_field': input_field,
                        'status': 'working',
                        'behavior': f'Alert triggered: {alert_text}',
                        'context': f"Successful XSS in {input_field}"
                    }
                    logger.info(f"Payload {payload} triggered alert in {input_field}: {alert_text}")
                    return result
                except TimeoutException:
                    time.sleep(1)  # Wait for potential delayed alert
                    continue
            
            # Handle interaction-based payloads (e.g., <select>, <button>)
            if any(event in payload.lower() for event in ['onclick', 'onchange']):
                try:
                    # Click elements that may trigger the payload
                    self.driver.find_element(By.TAG_NAME, 'select').click()
                    options = self.driver.find_elements(By.TAG_NAME, 'option')
                    if options:
                        options[0].click()
                    elif 'onclick' in payload.lower():
                        self.driver.find_element(By.TAG_NAME, 'button').click()
                except NoSuchElementException:
                    pass
            
            # Final check for alert
            try:
                alert = self.driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                result = {
                    'payload': payload,
                    'input_field': input_field,
                    'status': 'working',
                    'behavior': f'Alert triggered: {alert_text}',
                    'context': f"Successful XSS in {input_field} after interaction"
                }
                logger.info(f"Payload {payload} triggered alert in {input_field} after interaction: {alert_text}")
                return result
            except:
                result = {
                    'payload': payload,
                    'input_field': input_field,
                    'status': 'failed',
                    'behavior': 'No alert',
                    'context': f"No XSS detected in {input_field}"
                }
                logger.info(f"Payload {payload} did not trigger alert in {input_field}")
                return result
        
        except NoSuchElementException as e:
            logger.error(f"Element not found for payload {payload}: {e}")
            return {
                'payload': payload,
                'input_field': input_field,
                'status': 'error',
                'behavior': 'Test failed',
                'context': f"Error: Element not found - {str(e)}"
            }
        except TimeoutException as e:
            logger.error(f"Timeout for payload {payload}: {e}")
            return {
                'payload': payload,
                'input_field': input_field,
                'status': 'error',
                'behavior': 'Test failed',
                'context': f"Error: Timeout waiting for element - {str(e)}"
            }
        except WebDriverException as e:
            logger.error(f"WebDriver error for payload {payload}: {e}")
            return {
                'payload': payload,
                'input_field': input_field,
                'status': 'error',
                'behavior': 'Test failed',
                'context': f"Error: WebDriver issue - {str(e)}"
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
        errors = [r for r in results if r['status'] == 'error']
        
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
        
        if errors:
            with open('data/mshield_error_xss.txt', 'a', encoding='utf-8') as f:
                f.write(f"# Error XSS Payloads - {pd.Timestamp.now()}\n")
                f.write("# Payload | Expected Behavior | Actual Behavior | Context | Test Context\n")
                for r in errors:
                    f.write(f"{r['payload']} | Alert expected | {r['behavior']} | {r['context']} | {r['input_field']}\n")
            logger.info("Error payloads appended to data/mshield_error_xss.txt")
        
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
            input_selector='input#searchQuery',
            submit_selector='button#searchButton',
            input_field='search_bar'
        )
        
        # Run tests
        results = tester.test_payloads(payloads)
        
        # Save results
        save_results(results)
        
        # Log summary
        working_count = len([r for r in results if r['status'] == 'working'])
        failed_count = len([r for r in results if r['status'] == 'failed'])
        error_count = len([r for r in results if r['status'] == 'error'])
        logger.info(f"Tested {len(payloads)} payloads: {working_count} working, {failed_count} failed, {error_count} error")
        
    except Exception as e:
        logger.error(f"Main error: {e}")
        raise

if __name__ == "__main__":
    main()