MShield is a Python-based cybersecurity tool designed to detect Cross-Site Scripting (XSS) and Insecure Direct Object Reference (IDOR) vulnerabilities, empowering bug bounty hunters to secure small businesses and startups. Built as part of the Mendonça Legacy, MShield combines regex-based detection and machine learning (ML) to identify XSS payloads with >70% accuracy, laying the groundwork for IDOR detection. This project aims to generate income through bug bounties ($100-$500/report) while establishing a lasting impact in ethical hacking.

Features





Robust XSS Detection:





Regex Engine: Catches common and advanced XSS payloads (e.g., <script>, onerror=, %3Cscript%3E).



ML Classifier: Uses Logistic Regression to predict XSS with confidence scores (e.g., 92% for <script>alert(1)</script>).



Report-Ready Output: Generates detailed reports for HackerOne/Bugcrowd submissions.



IDOR Groundwork: Parses URLs for potential IDOR vulnerabilities (e.g., /api/user/123), with ML integration planned.



Ethical Testing: Safe for authorized platforms like TryHackMe and Juice Shop.



Scalable: Designed to expand to other vulnerabilities (e.g., SQL injection).



Beginner-Friendly: Clear code with comments, ideal for learning cybersecurity and ML.

Getting Started

Prerequisites





Python 3.11+: Install from python.org.



Virtual Environment: For isolated dependencies.



Libraries: numpy, pandas, scikit-learn, requests, jupyter.



Docker (optional): For running Juice Shop locally.



VS Code: Recommended with extensions (Python, Pylance, Code Runner, Jupyter, GitLens, Markdown All in One, REST Client, Regex Previewer, Docker).

Installation





Clone the Repository:

git clone https://github.com/your-username/mshield.git
cd mshield



Set Up Virtual Environment:

python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows



Install Dependencies:

pip install numpy pandas scikit-learn requests jupyter



Install VS Code Extensions:





Search Ctrl+Shift+X in VS Code for: ms-python.python, ms-python.vscode-pylance, formulahendry.code-runner, ms-toolsai.jupyter, eamodio.gitlens, yzhang.markdown-all-in-one, humao.rest-client, bms.regex-previewer, ms-azuretools.vscode-docker.



Select Python interpreter: Ctrl+Shift+P → “Python: Select Interpreter” → ./venv/bin/python.

Usage





Run MShield XSS Checker:





Save mshield_xss_checker.py from the repository.



Run in VS Code with Code Runner (Ctrl+Alt+N) or terminal:

python mshield_xss_checker.py



Test Inputs:





Default inputs include <script>alert('xss')</script>, <img src=x onerror=alert(1)>, and safe strings.



Add custom inputs in test_inputs list to test on TryHackMe or Juice Shop.



Example Output:

Input: <script>alert('xss')</script>
Regex Result: XSS Detected: Matches pattern '<\s*script\b[^>]*>[^<]*<\s*/\s*script\s*>'
ML Result: XSS Detected (ML Confidence: 92%)
Final Result: XSS Detected
Report:
MShield XSS Report
Input: <script>alert('xss')</script>
Regex: XSS Detected: Matches pattern '<\s*script\b[^>]*>[^<]*<\s*/\s*script\s*>'
ML: XSS Detected (ML Confidence: 92%)
Recommendation: Sanitize input to prevent XSS.



Test on Juice Shop:





Run Juice Shop: docker run -p 8888:3000 bkimminich/juice-shop.



Use REST Client to send inputs (e.g., <script>alert(1)</script>) to forms.



Feed results to mshield_xss_checker.py.

Ethical Guidelines





Authorized Testing Only: Use MShield on platforms like TryHackMe, Hack The Box, or bug bounty programs (HackerOne, Bugcrowd) with explicit permission.



Responsible Disclosure: Report vulnerabilities to program owners with clear steps, impact, and PoC (e.g., <script>alert(1)</script>).



Follow Rules: Adhere to HackerOne/Bugcrowd guidelines to avoid legal issues.

Roadmap





Week 1 (June 24-30, 2025):





Build/test MShield XSS checker (mshield_xss_checker.py).



Prep XSS dataset, train ML model.



Start IDOR parser (mshield_idor_parser.py).



Find small business bounty programs.



Future:





Add IDOR ML detection.



Expand to SQL injection and other vulnerabilities.



Develop Flask/FastAPI UI for real-time testing.



Target $1,000+/month in bounties.

Contributing

Contributions are welcome to grow the Mendonça Legacy! To contribute:





Fork the repository.



Create a branch: git checkout -b feature/your-feature.



Commit changes: git commit -m "Add your feature".



Push to branch: git push origin feature/your-feature.



Open a pull request.

License

MIT License – Free to use, modify, and distribute.

Contact





Author: [Your Name] (Mendonça Legacy)



GitHub: your-username



Email: [your-email@example.com] (for bug bounty inquiries)

Acknowledgments





Inspired by TryHackMe, Juice Shop, HackerOne, and Bugcrowd.



Built with Python, Scikit-learn, and VS Code.



Dedicated to the Mendonça Legacy in cybersecurity.

MShield: Protecting the web, one bounty at a time.
