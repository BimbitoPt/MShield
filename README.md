MShield
Overview
MShield is a Python-based XSS (Cross-Site Scripting) detection tool designed to identify malicious payloads in web inputs. Built by Mendonça, it targets 75% detection accuracy by Week 2 (July 6, 2025) and a $50-$100 bug bounty by Week 4 (July 20, 2025). MShield uses regex and rule-based analysis, with plans for ML integration, to support bug bounty hunting and future SaaS development.
Features

Detects common XSS payloads (e.g., <script>alert('xss')</script>, <img src=x onerror=alert(1)>).
Stores test payloads in mshield/data/mshield_xss_data.csv for analysis.
Logs debugging info to mshield/logs/debug.log.
Roadmap: Add SVG detection, ML-based analysis, SaaS for SMEs ($400/month by month 3).

Setup

Clone the repo:git clone https://github.com/[YOUR_USERNAME]/mshield.git
cd mshield


Install dependencies:pip install pandas


Create data structure:mkdir -p mshield/data mshield/logs
touch mshield/data/mshield_xss_data.csv
touch mshield/logs/debug.log


Add initial payloads to mshield/data/mshield_xss_data.csv (see mshield_xss_data.csv).

Usage

Run mshield_xss_checker_v2.py (WIP) to analyze payloads:python mshield/scripts/mshield_xss_checker_v2.py


Test payloads from TryHackMe or safe sources (e.g., <svg onload=alert(1)>).
Debug errors in mshield/logs/debug.log.

Data

mshield_xss_data.csv:payload,source,is_malicious,notes
<script>alert('xss')</script>,TryHackMe,True,Basic XSS payload for testing
<img src=x onerror=alert(1)>,Safe,True,Image-based XSS, common in forms



Roadmap

Week 2 (July 6, 2025): Collect 20 payloads, achieve 75% detection accuracy.
Week 4 (July 20, 2025): Submit 1 XSS report ($50-$100).
Month 3 (September 2025): Add ML detection, pitch to 5-10 SMEs ($100-$300).
Month 6 (December 2025): Launch SaaS with 20 users ($400/month).

Contributing

Add payloads to mshield_xss_data.csv.
Submit issues/PRs to https://github.com/[YOUR_USERNAME]/mshield.
Contact: DM @MendoncaVibe on X.

License
MIT License © 2025 Mendonça
