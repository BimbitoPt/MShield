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
from selenium.webdriver.common.action_chains import ActionChains
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
            time.sleep(2)
    
    def find_element_with_fallback(self, selectors: List[str], description: str) -> webdriver.remote.webelement.WebElement:
        """Try multiple selectors to find an element."""
        for selector in selectors:
            try:
                element = WebDriverWait(self.driver, 10).until(
                    EC.element_to_be_clickable((By.CSS_SELECTOR, selector))
                )
                if element.is_displayed() and element.size['height'] > 0 and element.size['width'] > 0:
                    logger.info(f"Found {description} with selector: {selector}")
                    return element
            except TimeoutException:
                logger.warning(f"Selector {selector} failed for {description}")
                continue
        raise TimeoutException(f"No valid {description} selector found: {selectors}")
    
    def handle_alerts(self) -> str:
        """Handle all alerts until none are present and return the last alert text."""
        alert_text = ""
        max_attempts = 10  # Prevent infinite loops
        attempt = 0
        
        while attempt < max_attempts:
            try:
                alert = WebDriverWait(self.driver, 2).until(EC.alert_is_present())
                alert_text = alert.text
                alert.accept()
                logger.info(f"Handled alert with text: {alert_text}")
                time.sleep(0.5)  # Brief pause to allow additional alerts
                # Disable future alerts
                self.driver.execute_script("window.alert = function() {}; window.onalert = null;")
                attempt += 1
            except TimeoutException:
                logger.info("No more alerts detected")
                break
            except Exception as e:
                logger.warning(f"Error handling alert: {e}")
                break
        
        return alert_text
    
    def dismiss_overlay(self):
        """Dismiss or wait for any overlays to disappear."""
        try:
            self.handle_alerts()
            overlays = self.driver.find_elements(By.CSS_SELECTOR, 'div.cdk-overlay-backdrop, div.modal, div.overlay, div.mat-mdc-dialog-container')
            for overlay in overlays:
                try:
                    if overlay.is_displayed():
                        self.driver.execute_script("arguments[0].style.display = 'none';", overlay)
                        logger.info("Hid overlay via JavaScript")
                        time.sleep(1)
                except Exception as e:
                    logger.warning(f"Failed to hide overlay: {e}")
            try:
                WebDriverWait(self.driver, 5).until_not(
                    EC.presence_of_element_located((By.CSS_SELECTOR, 'div.cdk-overlay-backdrop.cdk-overlay-backdrop-showing'))
                )
                logger.info("Confirmed overlays are dismissed")
            except TimeoutException:
                logger.warning("Overlay dismissal timed out, proceeding anyway")
        except Exception as e:
            logger.warning(f"Error dismissing overlays: {e}, proceeding anyway")
    
    def reset_page_state(self):
        """Reset page state by clearing inputs, dismissing alerts, and reloading the page."""
        try:
            # Handle any existing alerts
            self.handle_alerts()
            # Disable alerts and reset page
            self.driver.execute_script("window.onbeforeunload = null; window.alert = null; window.location.reload();")
            self.driver.get(self.url)
            self.wait_for_angular()
            # Clear any input fields
            inputs = self.driver.find_elements(By.CSS_SELECTOR, "input, textarea")
            for input_elem in inputs:
                try:
                    self.driver.execute_script("arguments[0].value = '';", input_elem)
                except Exception:
                    pass
            logger.info("Page state fully reset")
        except Exception as e:
            logger.warning(f"Failed to reset page state: {e}")
            self.driver.get(self.url)  # Fallback
            self.wait_for_angular()
    
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
                    logger.warning(f"Failed to open search_bar: {e}")
        raise TimeoutException("Failed to open search_bar after retries")
    
    def test_payload(self, payload: str) -> Dict[str, str]:
        """Test a single payload in the search_bar with a single attempt."""
        try:
            self.reset_page_state()
            self.dismiss_overlay()  # Added to handle any overlays before testing
            self.ensure_search_bar_open()
            
            input_selectors = self.selectors['search_bar']['input']
            input_element = self.find_element_with_fallback(input_selectors, "search_bar input")
            field_info = {
                'id': input_element.get_attribute('id'),
                'placeholder': input_element.get_attribute('placeholder'),
                'name': input_element.get_attribute('name'),
                'class': input_element.get_attribute('class')
            }
            logger.info(f"Targeting search_bar with selector {input_selectors[0]}: {field_info}")
            
            self.driver.execute_script("""
                var mousedownEvent = new MouseEvent('mousedown', {bubbles: true});
                arguments[0].dispatchEvent(mousedownEvent);
                arguments[0].click();
                arguments[0].focus();
            """, input_element)
            logger.info("Activated search_bar input with mousedown, click, and focus")
            
            input_element.clear()
            for char in payload:
                input_element.send_keys(char)
                time.sleep(0.1)
            self.driver.execute_script("arguments[0].focus();", input_element)
            logger.info("Typed payload character-by-character and maintained focus")
            
            try:
                self.driver.execute_script(
                    "arguments[0].dispatchEvent(new KeyboardEvent('keydown', {'key': 'Enter', 'code': 'Enter', 'bubbles': true}));"
                    "arguments[0].dispatchEvent(new KeyboardEvent('keypress', {'key': 'Enter', 'code': 'Enter', 'bubbles': true}));"
                    "arguments[0].dispatchEvent(new KeyboardEvent('keyup', {'key': 'Enter', 'code': 'Enter', 'bubbles': true}));"
                    "var form = arguments[0].closest('form'); if (form) form.dispatchEvent(new Event('submit', {bubbles: true}));",
                    input_element
                )
                logger.info("Submitted search_bar with JavaScript ENTER key and form submit event")
            except Exception as e:
                logger.warning(f"JavaScript ENTER failed: {e}; falling back to Selenium ENTER")
                input_element.send_keys(Keys.ENTER)
                logger.info("Submitted search_bar with Selenium ENTER key")
            
            # Immediate alert check after submission
            time.sleep(1)  # Allow time for initial alerts
            alert_text = self.handle_alerts()
            if alert_text:
                result = {
                    'payload': payload,
                    'input_field': 'search_bar',
                    'status': 'working',
                    'behavior': f'Alert triggered: {alert_text}',
                    'context': "Successful XSS in search_bar (immediate handle)"
                }
                logger.info(f"Payload {payload} triggered alert in search_bar immediately: {alert_text}")
                rendered_html = self.driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
                logger.info(f"Rendered HTML after alert: {rendered_html[:500]}...")
                return result
            
            actions = ActionChains(self.driver)
            if any(event in payload.lower() for event in ['onclick', 'onchange']):
                try:
                    element = WebDriverWait(self.driver, 5).until(
                        EC.presence_of_element_located((By.XPATH, "//*[@onclick or @onchange]"))
                    )
                    actions.move_to_element(element).click().perform()
                    logger.info(f"Simulated click on element with {payload}")
                    time.sleep(1)  # Allow time for click-triggered alerts
                    alert_text = self.handle_alerts()
                    if alert_text:
                        result = {
                            'payload': payload,
                            'input_field': 'search_bar',
                            'status': 'working',
                            'behavior': f'Alert triggered: {alert_text}',
                            'context': "Successful XSS in search_bar (click simulation)"
                        }
                        logger.info(f"Payload {payload} triggered alert in search_bar after click: {alert_text}")
                        rendered_html = self.driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
                        logger.info(f"Rendered HTML after click: {rendered_html[:500]}...")
                        return result
                except (TimeoutException, NoSuchElementException) as e:
                    logger.warning(f"No clickable element found for {payload}: {e}")
            
            if any(event in payload.lower() for event in ['onfocus', 'ontoggle']):
                try:
                    element = WebDriverWait(self.driver, 5).until(
                        EC.presence_of_element_located((By.XPATH, "//*[@onfocus or @ontoggle]"))
                    )
                    for _ in range(2):  # Retry focus to catch delayed alerts
                        try:
                            self.driver.execute_script("arguments[0].focus();", element)
                            logger.info(f"Simulated focus on element with {payload}")
                        except WebDriverException:
                            self.handle_alerts()  # Handle any unexpected alerts during focus
                        time.sleep(1)  # Allow time for focus/toggle-triggered alerts
                    alert_text = self.handle_alerts()
                    if alert_text:
                        result = {
                            'payload': payload,
                            'input_field': 'search_bar',
                            'status': 'working',
                            'behavior': f'Alert triggered: {alert_text}',
                            'context': "Successful XSS in search_bar (focus/toggle simulation)"
                        }
                        logger.info(f"Payload {payload} triggered alert in search_bar after focus/toggle: {alert_text}")
                        rendered_html = self.driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
                        logger.info(f"Rendered HTML after focus/toggle: {rendered_html[:500]}...")
                        return result
                except (TimeoutException, NoSuchElementException) as e:
                    logger.warning(f"No focusable/toggleable element found for {payload}: {e}")
            
            rendered_html = self.driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
            if payload in rendered_html:
                result = {
                    'payload': payload,
                    'input_field': 'search_bar',
                    'status': 'working',
                    'behavior': 'Payload injected (no alert)',
                    'context': "Successful XSS detected via DOM inspection"
                }
                logger.info(f"Payload {payload} injected into DOM without alert")
                return result
            
            time.sleep(3)
            current_url = self.driver.current_url
            logger.info(f"Current URL after submission: {current_url}")
            self.driver.get(current_url)
            self.wait_for_angular()
            rendered_html = self.driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
            logger.info(f"Rendered HTML after submission: {rendered_html[:500]}...")
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
            
            result = {
                'payload': payload,
                'input_field': 'search_bar',
                'status': 'failed',
                'behavior': 'No alert or DOM change',
                'context': "No XSS detected in search_bar"
            }
            logger.info(f"Payload {payload} did not trigger alert or DOM change in search_bar")
            return result
        
        except (TimeoutException, ElementClickInterceptedException, ElementNotInteractableException) as e:
            logger.error(f"Error for payload {payload}: {e}")
            return {
                'payload': payload,
                'input_field': 'search_bar',
                'status': 'error',
                'behavior': 'Test failed',
                'context': f"Error: {str(e)}"
            }
        except NoSuchElementException as e:
            logger.error(f"Element not found for payload {payload}: {e}")
            return {
                'payload': payload,
                'input_field': 'search_bar',
                'status': 'error',
                'behavior': 'Test failed',
                'context': f"Error: Element not found - {str(e)}"
            }
        except WebDriverException as e:
            logger.error(f"WebDriver error for payload {payload}: {e}")
            alert_text = self.handle_alerts()
            if alert_text:
                result = {
                    'payload': payload,
                    'input_field': 'search_bar',
                    'status': 'working',
                    'behavior': f'Alert triggered: {alert_text}',
                    'context': "Successful XSS in search_bar (handled after WebDriverException)"
                }
                logger.info(f"Payload {payload} triggered alert in search_bar after WebDriverException: {alert_text}")
                rendered_html = self.driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
                logger.info(f"Rendered HTML after WebDriverException: {rendered_html[:500]}...")
                self.reset_page_state()
                return result
            return {
                'payload': payload,
                'input_field': 'search_bar',
                'status': 'error',
                'behavior': 'Test failed',
                'context': f"Error: WebDriver issue - {str(e)}"
            }

    def test_payloads(self, payloads: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Test search_bar payloads and return results."""
        results = []
        self.setup_driver()
        
        try:
            search_bar_payloads = [p for p in payloads if p['is_malicious'] == 'True' and p['input_field'] == 'search_bar']
            logger.info(f"Testing {len(search_bar_payloads)} search_bar payloads")
            for index, payload_dict in enumerate(search_bar_payloads, 1):
                logger.info(f"Processing payload {index} of {len(search_bar_payloads)}: {payload_dict['payload']}")
                max_retries = 3
                for retry in range(max_retries):
                    try:
                        result = self.test_payload(payload_dict['payload'])
                        results.append(result)
                        save_results(results)
                        self.reset_page_state()
                        break  # Exit retry loop on success
                    except WebDriverException as e:
                        logger.error(f"WebDriver error for payload {payload_dict['payload']} on retry {retry + 1}: {e}")
                        if retry < max_retries - 1:
                            logger.info("Reinitializing WebDriver to recover session")
                            self.teardown_driver()
                            self.setup_driver()
                            self.reset_page_state()
                        else:
                            logger.error(f"Max retries reached for payload {payload_dict['payload']}")
                            results.append({
                                'payload': payload_dict['payload'],
                                'input_field': 'search_bar',
                                'status': 'error',
                                'behavior': 'Test failed after retries',
                                'context': f"Error: {str(e)}"
                            })
                            save_results(results)
                            self.reset_page_state()
        except Exception as e:
            logger.error(f"Error during payload testing: {e}")
            if len(results) < len(search_bar_payloads):
                logger.info(f"Continuing with remaining {len(search_bar_payloads) - len(results)} payloads")
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
    """Main function to run automated XSS testing for search_bar."""
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
        
        working_count = len([r for r in results if r['status'] == 'working'])
        failed_count = len([r for r in results if r['status'] == 'failed'])
        error_count = len([r for r in results if r['status'] == 'error'])
        logger.info(f"Tested {len(results)} search_bar payloads: {working_count} working, {failed_count} failed, {error_count} error")
        
    except Exception as e:
        logger.error(f"Main error: {e}")
        raise

if __name__ == "__main__":
    main()