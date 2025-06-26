import pandas as pd
import logging
import os
import time
import csv
import json
from typing import List, Dict
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    TimeoutException,
    NoSuchElementException,
    WebDriverException,
    ElementClickInterceptedException,
    ElementNotInteractableException
)

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
    """Automate XSS payload testing for the search bar."""
    
    def __init__(self, url: str = "http://localhost:3000/#/search", input_field: str = "search_bar"):
        """Initialize tester for search bar."""
        self.url = url
        self.input_field = input_field
        self.driver = None
        try:
            with open('data/selectors.json', 'r', encoding='utf-8') as f:
                selector_data = json.load(f)
            self.selectors = {
                'search_bar': {
                    'input': ['input#mat-input-1', 'input.mat-mdc-input-element'],
                    'submit': [],
                    'icon': ['mat-icon.mat-search_icon-search']
                }
            }
            for d in selector_data:
                if d['field_type'] == 'search_bar':
                    self.selectors['search_bar']['input'] = [sel for sublist in d['input_selectors'] for sel in sublist['selectors']]
                    self.selectors['search_bar']['submit'] = []
                    self.selectors['search_bar']['icon'] = [
                        sel for sublist in d.get('submit_selectors', []) 
                        for sel in sublist['selectors'] if 'mat-search_icon-search' in sel
                    ] or ['mat-icon.mat-search_icon-search']
        except FileNotFoundError:
            logger.error("selectors.json not found; using fallback selectors")
            self.selectors = {
                'search_bar': {
                    'input': ['input#mat-input-1', 'input.mat-mdc-input-element'],
                    'submit': [],
                    'icon': ['mat-icon.mat-search_icon-search']
                }
            }
    
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
        """Close the WebDriver."""
        try:
            if self.driver:
                self.driver.quit()
                logger.info("WebDriver closed")
                self.driver = None
        except Exception as e:
            logger.error(f"Error closing WebDriver: {e}")
    
    def wait_for_angular(self):
        """Wait for Angular to finish rendering."""
        try:
            WebDriverWait(self.driver, 20).until(
                lambda d: d.execute_script(
                    "return window.getAllAngularTestabilities && window.getAllAngularTestabilities().every(function(t) { return t.isStable(); });"
                )
            )
            logger.info("Angular page stabilized")
        except Exception as e:
            logger.warning(f"Angular wait failed: {e}; falling back to sleep")
            time.sleep(5)
    
    def find_element_with_fallback(self, selectors: List[str], description: str) -> webdriver.remote.webelement.WebElement:
        """Try multiple selectors to find an element."""
        for selector in selectors:
            try:
                element = WebDriverWait(self.driver, 15).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, selector))
                )
                if element.is_displayed() and element.size['height'] > 0 and element.size['width'] > 0:
                    logger.info(f"Found {description} with selector: {selector}")
                    return element
            except TimeoutException:
                logger.warning(f"Selector {selector} failed for {description}")
                continue
        raise TimeoutException(f"No valid {description} selector found: {selectors}")
    
    def save_screenshot(self, payload: str, attempt: int, alert_detected: bool = False):
        """Save screenshot with attempt number, optionally for alert."""
        sanitized_payload = ''.join(c for c in payload[:10] if c.isalnum() or c in ['_', '-'])
        suffix = '_alert' if alert_detected else ''
        screenshot_path = f'mshield/logs/screenshot_{sanitized_payload}_attempt_{attempt}{suffix}_{time.strftime("%Y%m%d_%H%M%S")}.png'
        self.driver.save_screenshot(screenshot_path)
        logger.info(f"Screenshot saved: {screenshot_path}")
    
    def handle_alerts(self) -> str:
        """Handle all alerts and return the last alert text, saving a screenshot."""
        alert_text = ""
        for _ in range(5):
            try:
                alert = WebDriverWait(self.driver, 15).until(EC.alert_is_present())
                alert_text = alert.text
                self.save_screenshot("", 1, alert_detected=True)  # Save screenshot of alert
                alert.accept()
                logger.info(f"Handled alert with text: {alert_text}")
                time.sleep(1)  # Wait for potential additional alerts
            except TimeoutException:
                break
        return alert_text
    
    def dismiss_overlay(self):
        """Dismiss or wait for any overlays to disappear."""
        try:
            overlays = self.driver.find_elements(By.CSS_SELECTOR, 'div.cdk-overlay-backdrop, div.modal, div.overlay, div.mat-mdc-dialog-container')
            for overlay in overlays:
                try:
                    if overlay.is_displayed():
                        self.driver.execute_script("arguments[0].style.display = 'none';", overlay)
                        logger.info("Hid overlay via JavaScript")
                        time.sleep(2)  # Increased delay to ensure overlay is gone
                except Exception as e:
                    logger.warning(f"Failed to hide overlay: {e}")
            WebDriverWait(self.driver, 5).until_not(
                EC.presence_of_element_located((By.CSS_SELECTOR, 'div.cdk-overlay-backdrop.cdk-overlay-backdrop-showing'))
            )
            logger.info("Confirmed overlays are dismissed")
        except TimeoutException:
            logger.info("No overlays found or dismissal timed out")
    
    def reset_page_state(self):
        """Reset page state by clearing inputs, dismissing overlays, and navigating to the search URL."""
        try:
            self.dismiss_overlay()
            inputs = self.driver.find_elements(By.CSS_SELECTOR, "input, textarea")
            for input_elem in inputs:
                try:
                    self.driver.execute_script("arguments[0].value = '';", input_elem)
                except:
                    pass
            self.driver.get(self.url)
            self.wait_for_angular()
            logger.info("Page state reset for search bar")
        except Exception as e:
            logger.warning(f"Failed to reset page state: {e}")
    
    def ensure_search_bar_open(self):
        """Ensure the search bar is open and in the correct state."""
        input_selectors = self.selectors['search_bar']['input']
        icon_selectors = self.selectors['search_bar']['icon']
        
        for attempt in range(1, 4):
            try:
                input_element = WebDriverWait(self.driver, 5).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, input_selectors[0]))
                )
                classes = input_element.get_attribute('class')
                if input_element.is_displayed() and input_element.size['height'] > 0 and 'mat-mdc-input-element' in classes:
                    logger.info(f"Search bar is open with classes: {classes}")
                    self.driver.execute_script("arguments[0].focus();", input_element)
                    return
            except (TimeoutException, ElementNotInteractableException):
                logger.info(f"Search bar is closed; attempting to open (attempt {attempt})")
                try:
                    icon = self.find_element_with_fallback(icon_selectors, "search icon")
                    self.driver.execute_script("arguments[0].scrollIntoView(true);", icon)
                    icon.click()
                    logger.info("Clicked search icon to open search bar")
                    WebDriverWait(self.driver, 5).until(
                        EC.element_to_be_clickable((By.CSS_SELECTOR, input_selectors[0]))
                    )
                    input_element = self.driver.find_element(By.CSS_SELECTOR, input_selectors[0])
                    self.driver.execute_script("arguments[0].focus();", input_element)
                    return
                except Exception as e:
                    logger.warning(f"Failed to open search bar: {e}")
        raise TimeoutException("Failed to open search bar after retries")
    
    def test_payload(self, payload: str) -> Dict[str, str]:
        """Test a single payload in the search bar with retries."""
        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                # Reset page state and dismiss overlays
                self.reset_page_state()
                
                # Ensure search bar is open and focused
                self.ensure_search_bar_open()
                
                # Get selectors
                input_selectors = self.selectors['search_bar']['input']
                
                # Find input element
                input_element = self.find_element_with_fallback(input_selectors, "search_bar input")
                field_info = {
                    'id': input_element.get_attribute('id'),
                    'placeholder': input_element.get_attribute('placeholder'),
                    'name': input_element.get_attribute('name'),
                    'class': input_element.get_attribute('class')
                }
                logger.info(f"Targeting search_bar with selector {input_selectors[0]}: {field_info}")
                
                # Activate input with mousedown, click, and focus
                self.driver.execute_script("""
                    var mousedownEvent = new MouseEvent('mousedown', {bubbles: true});
                    arguments[0].dispatchEvent(mousedownEvent);
                    arguments[0].click();
                    arguments[0].focus();
                """, input_element)
                logger.info("Activated search bar input with mousedown, click, and focus")
                
                # Clear and type payload character-by-character
                input_element.clear()
                for char in payload:
                    input_element.send_keys(char)
                    time.sleep(0.1)
                self.driver.execute_script("arguments[0].focus();", input_element)
                logger.info("Typed payload character-by-character and maintained focus")
                
                # Simulate ENTER key with JavaScript
                try:
                    self.driver.execute_script(
                        "arguments[0].dispatchEvent(new KeyboardEvent('keydown', {'key': 'Enter', 'code': 'Enter', 'bubbles': true}));"
                        "arguments[0].dispatchEvent(new KeyboardEvent('keypress', {'key': 'Enter', 'code': 'Enter', 'bubbles': true}));"
                        "arguments[0].dispatchEvent(new KeyboardEvent('keyup', {'key': 'Enter', 'code': 'Enter', 'bubbles': true}));"
                        "var form = arguments[0].closest('form'); if (form) form.dispatchEvent(new Event('submit', {bubbles: true}));",
                        input_element
                    )
                    logger.info("Submitted search bar with JavaScript ENTER key and form submit event")
                except Exception as e:
                    logger.warning(f"JavaScript ENTER failed: {e}; falling back to Selenium ENTER")
                    input_element.send_keys(Keys.ENTER)
                    logger.info("Submitted search bar with Selenium ENTER key")
                
                # Immediate alert check with short delay
                time.sleep(2)  # Short initial wait to catch alert
                alert_text = self.handle_alerts()
                if alert_text:
                    self.save_screenshot(payload, attempt, alert_detected=True)
                    result = {
                        'payload': payload,
                        'input_field': 'search_bar',
                        'status': 'working',
                        'behavior': f'Alert triggered: {alert_text}',
                        'context': "Successful XSS in search_bar (immediate handle)"
                    }
                    logger.info(f"Payload {payload} triggered alert in search_bar immediately: {alert_text}")
                    return result
                
                # Wait for rendering and navigate to result URL
                time.sleep(5)  # Reduced delay to 5 seconds after initial check
                current_url = self.driver.current_url
                logger.info(f"Current URL after submission: {current_url}")
                self.driver.get(current_url)
                self.wait_for_angular()
                
                # Debug: Check rendered HTML
                rendered_html = self.driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
                logger.info(f"Rendered HTML after submission: {rendered_html[:500]}...")
                
                # Capture screenshot
                self.save_screenshot(payload, attempt)
                
                # Additional alert check
                alert_text = self.handle_alerts()
                if alert_text:
                    result = {
                        'payload': payload,
                        'input_field': 'search_bar',
                        'status': 'working',
                        'behavior': f'Alert triggered: {alert_text}',
                        'context': "Successful XSS in search_bar"
                    }
                    logger.info(f"Payload {payload} triggered alert in search_bar: {alert_text}")
                    return result
                
                # No alert; retry if not last attempt
                if attempt < max_retries:
                    logger.info(f"Payload {payload} did not trigger alert on attempt {attempt}; retrying")
                    continue
                
                result = {
                    'payload': payload,
                    'input_field': 'search_bar',
                    'status': 'failed',
                    'behavior': 'No alert',
                    'context': "No XSS detected in search_bar"
                }
                logger.info(f"Payload {payload} did not trigger alert in search_bar after {max_retries} attempts")
                return result
            
            except (TimeoutException, ElementClickInterceptedException, ElementNotInteractableException) as e:
                self.save_screenshot(payload, attempt)
                logger.error(f"Error for payload {payload} on attempt {attempt}: {e}")
                if attempt < max_retries:
                    logger.info(f"Retrying payload {payload} due to error")
                    continue
                return {
                    'payload': payload,
                    'input_field': 'search_bar',
                    'status': 'error',
                    'behavior': 'Test failed',
                    'context': f"Error: {str(e)}"
                }
            except NoSuchElementException as e:
                self.save_screenshot(payload, attempt)
                logger.error(f"Element not found for payload {payload}: {e}")
                return {
                    'payload': payload,
                    'input_field': 'search_bar',
                    'status': 'error',
                    'behavior': 'Test failed',
                    'context': f"Error: Element not found - {str(e)}"
                }
            except WebDriverException as e:
                self.save_screenshot(payload, attempt)
                logger.error(f"WebDriver error for payload {payload}: {e}")
                # Attempt to handle alert if it caused the exception
                try:
                    alert_text = self.handle_alerts()
                    if alert_text:
                        self.save_screenshot(payload, attempt, alert_detected=True)  # Save alert screenshot
                        result = {
                            'payload': payload,
                            'input_field': 'search_bar',
                            'status': 'working',
                            'behavior': f'Alert triggered: {alert_text}',
                            'context': "Successful XSS in search_bar (handled after WebDriverException)"
                        }
                        logger.info(f"Payload {payload} triggered alert in search_bar after WebDriverException: {alert_text}")
                        return result
                except Exception as ex:
                    logger.warning(f"Failed to handle alert after WebDriverException: {ex}")
                return {
                    'payload': payload,
                    'input_field': 'search_bar',
                    'status': 'error',
                    'behavior': 'Test failed',
                    'context': f"Error: WebDriver issue - {str(e)}"
                }
    
    def test_payloads(self, payloads: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Test search bar payloads and return results."""
        results = []
        self.setup_driver()
        
        try:
            search_bar_payloads = [p for p in payloads if p['is_malicious'] == 'True' and p['input_field'] == 'search_bar']
            logger.info(f"Testing {len(search_bar_payloads)} search_bar payloads")
            for payload_dict in search_bar_payloads:
                result = self.test_payload(payload_dict['payload'])
                results.append(result)
        finally:
            self.teardown_driver()
        
        return results

def save_results(results: List[Dict[str, str]]):
    """Save test results to CSV and log files."""
    try:
        df = pd.DataFrame(results)
        df.to_csv('data/auto_test_results.csv', index=False, quoting=csv.QUOTE_ALL)
        logger.info("Results saved to data/auto_test_results.csv")
        
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
    """Main function to run automated XSS testing for search bar."""
    try:
        df = pd.read_csv(
            'data/mshield_xss_data.csv',
            quoting=csv.QUOTE_ALL,
            dtype={'payload': str, 'source': str, 'is_malicious': str, 'notes': str, 'input_field': str},
            keep_default_na=False,
            escapechar='\\'
        )
        payloads = df.to_dict('records')
        
        tester = XSSAutoTester()
        results = tester.test_payloads(payloads)
        save_results(results)
        
        working_count = len([r for r in results if r['status'] == 'working'])
        failed_count = len([r for r in results if r['status'] == 'failed'])
        error_count = len([r for r in results if r['status'] == 'error'])
        logger.info(f"Tested {len(results)} search_bar payloads: {working_count} working, {failed_count} failed, {error_count} error")
        
    except Exception as e:
        logger.error(f"Main error: {e}")
        raise

if __name__ == "__main__":
    main()