# MShield Data Gathering, Labeling, and Debugging Template

**Purpose**: Guide data collection, labeling, and debugging for MShield, an ML cybersecurity bug bounty AI for XSS/IDOR detection, ensuring robust inputs (150-200) and error-free code.  
**Author**: Mendonça Legacy  
**Usage**: Fill sections, use with TryHackMe Premium, Juice Shop (Docker), and VS Code (Python, Pylance, Code Runner, Jupyter, GitLens, Markdown All in One, REST Client, Regex Previewer, Docker). Save in `mshield/templates/`, track in Notion/Trello.  
**Ethical Note**: Collect data only from authorized sources (e.g., `scope.json`: `*.tryhackme.com`, `localhost:8888`).  

## 1. Data Gathering
### Objective
- **Goal**: [e.g., Collect 100 Juice Shop inputs (50 XSS, 50 safe), 50 TryHackMe inputs (25 XSS, 25 safe) by Week 2]
- **MShield Feature**: [e.g., XSS detection, IDOR parsing]
- **Deliverable**: [e.g., `mshield_xss_data.csv` with 150 inputs, `exploits.txt`]

### Sources
- [ ] **Juice Shop**:
  - Setup: `docker run -p 8888:3000 bkimminich/juice-shop`
  - Scope: `localhost:8888` (per `scope.json`)
  - Inputs: [e.g., 50 XSS payloads (`<script>alert(1)</script>`), 50 safe (`hello world`)]
  - Method: [e.g., Manual input via browser, REST Client for API]
- [ ] **TryHackMe Premium**:
  - Setup: Log into TryHackMe, access “OWASP Top 10: XSS” or “IDOR”
  - Scope: `*.tryhackme.com` (per `scope.json`)
  - Inputs: [e.g., 25 XSS payloads (`<img src=x onerror=alert(1)>`), 25 safe (`<div>content</div>`)]
  - Method: [e.g., Manual input via CTF fields, Python to log responses]
- [ ] **Other**: [e.g., PayloadsAllTheThings for XSS payloads]

### Collection Plan
- **Quantity**: [e.g., 20 inputs/day (10 Juice Shop, 10 TryHackMe)]
- **Format**: [e.g., Save in `mshield/mshield_xss_data.csv` or `mshield/exploits.txt`]
- **Tools**: [e.g., Python (requests, pandas), Jupyter, REST Client, Regex Previewer]
- **Steps**:
  1. [e.g., Setup Juice Shop: `docker pull bkimminich/juice-shop`]
  2. [e.g., Input `<script>alert(1)</script>` in Juice Shop form, log response]
  3. [e.g., Collect 10 TryHackMe XSS payloads, save in `exploits.txt`]
- **Validation**: [e.g., Check 50% safe/malicious balance, verify scope compliance]

### Notes
- **Blockers**: [e.g., Docker not installed]
- **Practice Tip**: [e.g., Test `<svg onload=alert(1)>` in Juice Shop]

## 2. Data Labeling
### Objective
- **Goal**: [e.g., Label 150 inputs as safe/malicious for XSS detection by Week 2]
- **MShield Feature**: [e.g., Train ML model in `mshield_xss_checker_v2.py`]
- **Deliverable**: [e.g., `mshield_xss_data.csv` with labeled inputs]

### Labeling Rules
- **Format**: [e.g., CSV: `input,label`]
  ```csv
  "<script>alert(1)</script>",malicious
  "hello world",safe
  ```
- **Malicious**: [e.g., `<script>`, `<svg>`, `<img onerror>`, `javascript:alert(1)`]
- **Safe**: [e.g., Plain text, `<p>`, `<div>`, sanitized inputs]
- **Edge Cases**: [e.g., `<script type="text/plain">` = safe]

### Process
- **Quantity**: [e.g., Label 20 inputs/day (10 Juice Shop, 10 TryHackMe)]
- **Tools**: [e.g., Python (pandas), Jupyter, Regex Previewer]
- **Steps**:
  1. [e.g., Load `mshield_xss_data.csv` in Jupyter]
  2. [e.g., Apply regex (`<script>`) to flag malicious inputs]
  3. [e.g., Manually review edge cases, save labels]
- **Validation**: [e.g., Check 50% safe/malicious balance, cross-check with `mshield_xss_checker.py` regex]

### Notes
- **Blockers**: [e.g., Unclear edge case labels]
- **Practice Tip**: [e.g., Label `<a href=javascript:alert(1)>` as malicious]

## 3. Debugging
### Objective
- **Goal**: [e.g., Resolve regex/ML errors in `check_scope.py`, `mshield_xss_checker_v2.py`]
- **MShield Feature**: [e.g., Scope validation, XSS detection]
- **Deliverable**: [e.g., Error-free `check_scope.py`, debug log]

### Error Types
- [ ] **Regex**: [e.g., `KeyError` in `check_scope.py`, invalid pattern]
- [ ] **ML**: [e.g., NaN values in `mshield_xss_checker_v2.py`, scikit-learn errors]
- [ ] **JSON**: [e.g., Parsing errors in `scope.json`]
- [ ] **Other**: [e.g., `TypeError` in `generate_report.py`]

### Debugging Plan
- **Time Allocation**: [e.g., 2 hours/day]
- **Tools**: [e.g., Jupyter, Python (try/except), Pylance, Code Runner]
- **Steps**:
  1. [e.g., Reproduce error in Jupyter or `python script.py`]
  2. [e.g., Add try/except per `mshield_coding_template.md`]
  3. [e.g., Log errors to `mshield/logs/debug.log`]
  4. [e.g., Test fix with 5 inputs from `mshield_xss_data.csv`]
- **Logging** (per `mshield_coding_template.md`):
  ```python
  import logging
  logging.basicConfig(filename='mshield/logs/debug.log', level=logging.DEBUG)
  logging.debug('Error: %s', str(e))
  ```
- **Validation**: [e.g., Run `check_scope.py` on 10 URLs, verify 75% XSS accuracy]

### Notes
- **Blockers**: [e.g., Jupyter not installed]
- **Practice Tip**: [e.g., Add try/except to `check_scope.py` for JSON errors]

## 4. Submission
- Save in `mshield/templates/data_debug_template.md`.
- Commit to GitHub: `git add data_debug_template.md`, `git commit -m "Add data/debug template"`, `git push origin main`.
- Copy to Notion/Trello for tracking.
- Use with `prompt_engineer_template.md` to request Grok 3 assistance.