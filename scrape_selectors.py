import json
import logging
import os
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException

# Ensure directories exist
os.makedirs('mshield/logs', exist_ok=True)
os.makedirs('data', exist_ok=True)

# Configure logging
logging.basicConfig(
    filename='mshield/logs/scrape_selectors.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def setup_driver():
    """Set up Chrome WebDriver."""
    try:
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--window-size=1920,1080')
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(30)
        logger.info("WebDriver initialized for selector scraping")
        return driver
    except WebDriverException as e:
        logger.error(f"Failed to initialize WebDriver: {e}")
        raise

def wait_for_angular(driver):
    """Wait for Angular to finish rendering."""
    try:
        WebDriverWait(driver, 15).until(
            lambda d: d.execute_script(
                "return window.getAllAngularTestabilities && window.getAllAngularTestabilities().every(function(t) { return t.isStable(); });"
            )
        )
        logger.info("Angular page stabilized")
    except Exception as e:
        logger.warning(f"Angular wait failed: {e}; falling back to sleep")
        time.sleep(3)

def get_element_attributes(element):
    """Extract relevant attributes from a WebElement."""
    try:
        attributes = {
            'tag': element.tag_name,
            'id': element.get_attribute('id') or '',
            'class': element.get_attribute('class') or '',
            'name': element.get_attribute('name') or '',
            'matinput': element.get_attribute('matinput') or '',
            'placeholder': element.get_attribute('placeholder') or '',
            'type': element.get_attribute('type') or '',
            'formcontrolname': element.get_attribute('formcontrolname') or ''
        }
        # Get parent context
        try:
            parent = element.find_element(By.XPATH, '..')
            attributes['parent_tag'] = parent.tag_name
            attributes['parent_class'] = parent.get_attribute('class') or ''
        except:
            attributes['parent_tag'] = ''
            attributes['parent_class'] = ''
        return attributes
    except Exception as e:
        logger.warning(f"Error extracting attributes: {e}")
        return {}

def generate_css_selector(attributes):
    """Generate a CSS selector from element attributes."""
    selectors = []
    if attributes.get('id'):
        selectors.append(f"#{attributes['id']}")
    if attributes.get('matinput'):
        selectors.append('input[matinput]')
    if attributes.get('formcontrolname'):
        selectors.append(f"input[formcontrolname='{attributes['formcontrolname']}']")
    if attributes.get('name'):
        selectors.append(f"{attributes['tag']}[name='{attributes['name']}']")
    if attributes.get('placeholder'):
        selectors.append(f"{attributes['tag']}[placeholder='{attributes['placeholder']}']")
    if attributes.get('class'):
        class_clean = '.'.join(c for c in attributes['class'].split() if c)
        if class_clean:
            selectors.append(f"{attributes['tag']}.{class_clean}")
    return selectors or [f"{attributes['tag']}"]

def scrape_selectors(url, field_type):
    """Scrape input and submit elements for a given page."""
    driver = setup_driver()
    try:
        driver.get(url)
        wait_for_angular(driver)
        
        results = {'field_type': field_type, 'input_selectors': [], 'submit_selectors': []}
        
        # Find input elements (input, textarea)
        input_elements = driver.find_elements(By.CSS_SELECTOR, 'input, textarea')
        for element in input_elements:
            attrs = get_element_attributes(element)
            if attrs:
                selectors = generate_css_selector(attrs)
                results['input_selectors'].append({
                    'selectors': selectors,
                    'attributes': attrs
                })
                logger.info(f"Found input element: {attrs}")
        
        # Find potential submit elements (button, mat-icon, input[type=submit])
        submit_elements = driver.find_elements(By.CSS_SELECTOR, 'button, mat-icon, input[type="submit"]')
        for element in submit_elements:
            attrs = get_element_attributes(element)
            if attrs:
                selectors = generate_css_selector(attrs)
                results['submit_selectors'].append({
                    'selectors': selectors,
                    'attributes': attrs
                })
                logger.info(f"Found submit element: {attrs}")
        
        return results
    except Exception as e:
        logger.error(f"Error scraping selectors for {url}: {e}")
        return {'field_type': field_type, 'input_selectors': [], 'submit_selectors': []}
    finally:
        driver.quit()

def main():
    """Scrape selectors for Juice Shop pages."""
    pages = [
        {'url': 'http://localhost:3000/#/search', 'field_type': 'search_bar'},
        {'url': 'http://localhost:3000/#/profile', 'field_type': 'profile_bio'},
        {'url': 'http://localhost:3000/#/product/1', 'field_type': 'comments'}
    ]
    
    all_results = []
    for page in pages:
        logger.info(f"Scraping selectors for {page['field_type']} at {page['url']}")
        result = scrape_selectors(page['url'], page['field_type'])
        all_results.append(result)
    
    # Save to JSON
    with open('data/selectors.json', 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2)
    logger.info("Selectors saved to data/selectors.json")

if __name__ == "__main__":
    main()