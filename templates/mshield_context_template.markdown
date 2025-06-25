# MShield Context Template
*Last Updated: June 25, 2025*

## Project Overview
- **Name**: MShield
- **Goal**: Develop an XSS detection tool to achieve ≥95% accuracy by July 31, 2025, and secure a $50-$100 bug bounty by July 20, 2025.
- **Purpose**: Identify and classify XSS payloads in OWASP Juice Shop (`localhost:8888`) for portfolio enhancement and bug bounty submission.
- **Status**: 5/14 malicious payloads triggering (as of June 25, 2025), 100% detection accuracy in `mshield_xss_checker_v3.py`.
- **Income Target**: $225-$750 (Week 4, Portfolio).

## Environment
- **Testing Platform**: OWASP Juice Shop (`docker run --rm -p 8888:3000 bkimminich/juice-shop`).
- **Input Fields**: Search bar, product reviews, login form, profile bio.
- **Tools**:
  - **VS Code**: Python, Pylance, Code Runner, Jupyter, GitLens, Markdown, REST Client, Regex Previewer, Docker.
  - **Python**: `mshield_xss_checker_v3.py`, pandas, re, logging.
  - **Jupyter**: Regex testing, payload analysis.
  - **Docker**: Juice Shop container.
  - **GitHub**: Version control (`mshield` repo).
  - **Notion**: Progress tracking.
- **Files**:
  - `mshield/data/mshield_xss_data.csv`: Payload dataset.
  - `mshield/scripts/mshield_xss_checker_v3.py`: XSS detection script.
  - `mshield/data/xss_results.csv`: Detection results.
  - `mshield/data/mshield_working_xss.txt`: Working payloads log.
  - `mshield/data/mshield_failed_xss.txt`: Failed payloads log.
  - `mshield/templates/data_debug_template.md`: Debugging log.
  - `mshield/logs/xss_checker_v3.log`: Script logs.

## Workflow
- **Payload Testing**:
  - Run `python mshield/scripts/mshield_xss_checker_v3.py` to process `mshield_xss_data.csv`.
  - Test payloads in Juice Shop (search bar, product reviews, login form, profile bio).
  - Update `mshield_working_xss.txt` and `mshield_failed_xss.txt` with results.
- **Debugging**:
  - Use Jupyter for regex testing (e.g., `EVENT_PATTERN`).
  - Log issues in `data_debug_template.md` (test entries, debug entries).
- **Commits**: `git add`, `git commit`, `git push` to `mshield` repo.
- **Notion Updates**: Log progress, blockers, and next steps.

## Chat Structure
- **Issue**: Describe the problem (e.g., payload misclassification, script error).
- **Goal**: Specify desired outcome (e.g., correct context, increase triggers).
- **Details**:
  - Payload(s): List payloads (e.g., `<div onmouseover=alert('xss')>`).
  - Test Context: Search bar, product reviews, etc.
  - Expected Behavior: Alert triggered, is_xss=True, etc.
  - Actual Behavior: No alert, misclassified context, etc.
  - Relevant Files: `mshield_xss_checker_v3.py`, `xss_results.csv`, etc.
- **Request**: Fix script, update files, test payloads, debug regex, etc.
- **Blockers**: Sanitization, regex errors, Juice Shop crashes, etc.

## Debugging Format
- **Test Entry** (data_debug_template.md):
  ```markdown
  - **Date**: [Date, e.g., June 25, 2025]
  - **Payload**: [Payload, e.g., <div onmouseover=alert('xss')>]
  - **Expected**: [e.g., is_xss=True, alert triggered]
  - **Actual**: [e.g., No alert, misclassified]
  - **Feature**: [e.g., event_regex, iframe_a_embed_regex]
  - **Error**: [e.g., No alert, incorrect context]
  - **Fix**: [e.g., Test in product reviews, adjust regex]
  - **Test**: [e.g., Search bar, product reviews]
  - **Notes**: [e.g., Needs mouseover interaction]
  ```
- **Debug Entry**:
  ```markdown
  - **Date**: [Date]
  - **Payload**: [Payload]
  - **Expected**: [Expected outcome]
  - **Actual**: [Actual outcome]
  - **Feature**: [Affected feature]
  - **Error**: [Error details]
  - **Fix**: [Applied fix]
  - **Test**: [Test context]
  - **Notes**: [Additional insights]
  ```

## Example Chat
**Issue**: `<div onmouseover=alert('xss')>` misclassified as working.  
**Goal**: Correct context to “Moderate likelihood”, test in product reviews.  
**Details**:  
- Payload: `<div onmouseover=alert('xss')>`  
- Test Context: Search bar  
- Expected: No alert, Moderate likelihood  
- Actual: Classified as High likelihood, no alert  
- Files: `mshield_xss_checker_v3.py`, `mshield_failed_xss.txt`  
**Request**: Update `analyze_context`, retest payload, log in `data_debug_template.md`.  
**Blockers**: Juice Shop sanitization, mouseover interaction.

## Schedule
- **Session**: 8 PM - 1:30 AM WEST (end by 12:30 AM to protect 5 AM - 6 AM sleep).
- **Tasks**: Test payloads, debug regex, commit changes, update Notion.
- **Sleep Protection**: Avoid caffeine, use blue-light-blocking glasses.

## Next Steps
- Increase triggering rate (target: 10/14 payloads).
- Add `<body>` regex to `mshield_xss_checker_v3.py`.
- Prepare bug bounty report by July 15, 2025.