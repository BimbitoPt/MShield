# [Vulnerability Type] in [Site] [Component]

**Program**: [Program Name]  
**Description**: MShield detected [payload] in [endpoint], triggering [effect].  
**Scope Compliance**: Tested within [in_scope asset, e.g., *.example.com] per [Program] guidelines.  

**Steps to Reproduce**:  
1. Navigate to [URL].  
2. Inject [payload] in [field/parameter].  
3. Observe [effect, e.g., alert popup].  

**Impact**: [e.g., Cookie theft, session hijacking, unauthorized script execution].  
**Proof of Concept (PoC)**:  
```html
[payload, e.g., <script>alert(1)</script>]
```

**MShield Output**:  
```json
[Insert JSON/CSV result, e.g., {"regex_result": "XSS Detected", "ml_result": "XSS Detected (95%)"}]
```

**Recommendation**: [e.g., Sanitize user inputs, implement Content Security Policy (CSP)].  
**Attachments**: [e.g., Screenshot of alert, video PoC (optional)].  
**Reported By**: Mendonça Legacy via MShield AI