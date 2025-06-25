# MShield Prompt Engineer Template

**Purpose**: Guide Grok 3 to generate consistent, ethical, beginner-friendly outputs (code, plans, tasks) for MShield, an ML cybersecurity bug bounty AI for XSS/IDOR detection.  
**Author**: Mendonça Legacy  
**Usage**: Fill in sections, submit to Grok 3, review outputs in VS Code/Notion.  
**Ethical Note**: Outputs must enforce scope compliance (e.g., `scope.json`) and align with bug bounty rules (e.g., TryHackMe, HackerOne).  

## 1. Request Type
- [ ] Code (e.g., Python script using `mshield_coding_template.md`)
- [ ] Planning (e.g., roadmap, tasks)
- [ ] Research (e.g., SMEs, CTFs)
- [ ] Other: [Specify]

## 2. Objective
- **Goal**: [e.g., Code `check_scope` to validate URLs against `scope.json` for TryHackMe CTFs]
- **MShield Feature**: [e.g., XSS detection, scope compliance, report generation]
- **Deliverable**: [e.g., `check_scope.py`, Notion plan, Trello tasks]

## 3. Context
- **Skill Level**: 
- **Tools**: [e.g., TryHackMe Premium, VS Code (Python, Pylance, Code Runner, Jupyter, GitLens, Markdown All in One, REST Client, Regex Previewer, Docker)]
- **Templates**: [e.g., `scope.json`, `bug_report_template.md`, `mshield_coding_template.md`]
- **Testing Environment**: [e.g., TryHackMe CTFs (`*.tryhackme.com`), Juice Shop]
- **Constraints**: [e.g., No local file I/O for pygame, ethical testing only]

## 4. Requirements
- **Functionality**: [e.g., Validate URLs against `scope.json`, generate report in `bug_report_template.md`]
- **Input**: [e.g., URL string, `scope.json` file]
- **Output**: [e.g., Boolean (in-scope True/False), Markdown report]
- **Dependencies**: [e.g., Python (re, json, requests, scikit-learn)]
- **Ethical Guardrails**: [e.g., Enforce `scope.json`, warn about unauthorized testing]
- **Success Criteria**: [e.g., 80% XSS accuracy, scope-compliant reports]

## 5. Example
- **Prompt Example**:
  ```
  Create a Python script to check if a URL is in scope using `scope.json`. Use `mshield_coding_template.md`. Input: URL string, `scope.json`. Output: Boolean (True if in-scope). Test on TryHackMe URLs (`*.tryhackme.com`). Log errors, ensure ethical testing.
  ```
- **Expected Output**: [e.g., `check_scope.py` with logging, CLI, TryHackMe test cases]

## 6. Additional Notes
- **Preferences**: [e.g., Minimal code today, focus on planning]
- **Blockers**: [e.g., Need help with TryHackMe setup]
- **Practice Tip**: [e.g., Add a test case to `scope.json`]

## 7. Submission
- Submit this template to Grok 3 via text input.
- Review output in VS Code (`mshield/templates/`) or Notion.
- Commit to GitHub: `git add prompt_engineer_template.md`, `git commit -m "Add prompt template"`, `git push origin main`.