# Week 5: Web Security - Vulnerability Scanning

**Module**: Networks and System Security  
**Student**: Zohaib Khokhar  
**Date**: December 2025  
**Topic**: Web Application Vulnerability Scanning with Wapiti

---

## Workshop Overview

This workshop focused on automated vulnerability scanning using Wapiti, a Python-based black-box testing tool. Wapiti crawls web applications and injects payloads to identify security weaknesses - simulating how an attacker would probe for vulnerabilities.

**Ethical rule**: Only scan deliberately vulnerable training applications (Google Gruyere, OWASP Juice Shop), never production websites without explicit permission.

---

## What is Black-Box Testing?

Wapiti performs black-box testing - no source code access, just interacting through the web interface like an attacker would:

1. **Crawls** the target to discover URLs and forms
2. **Injects** malicious payloads into parameters
3. **Analyzes** responses to identify vulnerabilities
4. **Reports** findings with severity ratings

### Vulnerabilities Detected

- **XSS (Cross-Site Scripting)**: JavaScript injection
- **SQL Injection**: Database query manipulation
- **Command Injection**: System command execution
- **File Inclusion**: Unauthorized file access
- **Insecure File Uploads**: Malicious file uploads
- **SSRF**: Server-side request forgery

---

## Setup

### Installation
```bash
pip install wapiti3
wapiti --version
```

### Target Applications
- **Google Gruyere**: Created instance at https://google-gruyere.appspot.com/789012/
- **OWASP Juice Shop**: https://juice-shop.herokuapp.com

Both are intentionally vulnerable training apps - scanning anything else without permission is illegal.

---

## Running Scans

### Basic Command
```bash
wapiti -u "https://google-gruyere.appspot.com/789012/" -o gruyere_scan.html
```

The scan took ~10-15 minutes and systematically:
1. Discovered links and forms
2. Tested parameters with payloads
3. Identified vulnerable injection points
4. Generated HTML report

### Report Structure
- **Summary**: Vulnerabilities by severity
- **Details**: Each finding with vulnerable URL, payload, HTTP request/response, and remediation advice

---

## Key Vulnerabilities Found

### 1. Cross-Site Scripting (XSS)

**Location**: User snippet feature  
**Payload**: `<script>alert('XSS')</script>`

Application displayed user input without sanitization, executing injected JavaScript.

**Impact**: Steal cookies, redirect users, modify content, keylogging

**Real example**: 2018 British Airways breach - XSS compromised 380,000 customer records

**Fix**: Sanitize input, use output encoding

### 2. SQL Injection

**Location**: Login form  
**Payload**: `admin' OR '1'='1`

Application concatenated user input into SQL queries:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = 'anything'
```

**Impact**: Bypass authentication, extract database, modify data

**Real example**: 2015 TalkTalk breach via SQLi - 157,000 records exposed, £77M cost

**Fix**: Use parameterized queries (prepared statements)

### 3. File Inclusion

**Payload**: `../../../../etc/passwd`

Path traversal to access files outside intended directory.

**Impact**: Read sensitive files, access source code

**Fix**: Validate against whitelist, use absolute paths

### 4. Command Injection

**Payload**: `; cat /etc/passwd`

Application passed user input to shell commands, allowing arbitrary command execution.

**Impact**: Complete server compromise

**Fix**: Never pass user input to shell. Use language-native libraries instead.

---

## Practical Insights

### False Positives
Not all findings are real vulnerabilities. Wapiti flagged potential XSS that manual testing revealed was actually sanitized. **Lesson**: Always manually verify automated findings.

### Scan Limitations
- **JavaScript-heavy apps**: Wapiti can't execute JavaScript, misses SPA content
- **Authentication**: Need manual setup for protected areas
- **Rate limiting**: Aggressive scanning triggers blocks - use throttling options

### What Scanners Miss
- Business logic flaws
- Race conditions  
- Complex authentication flows
- Context-specific issues requiring human judgment

Automated scanning finds "low-hanging fruit" but can't replace manual penetration testing.

---

## Ethical Considerations

**Legal**: Unauthorized scanning violates Computer Misuse Act (UK) and similar laws worldwide. Even unintentional scanning can result in criminal charges.

**Responsible disclosure**: If you find vulnerabilities during authorized testing, report privately and allow time to patch before public disclosure.

**Bug bounty programs**: Companies like Google, Facebook run programs that explicitly authorize testing and pay for findings - the legal way to practice.

---

## Reflection

Running automated scans made web vulnerabilities tangible. Seeing `admin' OR '1'='1` actually bypass authentication was far more impactful than just reading about SQL injection. The ease of finding critical vulnerabilities with a single command explains why security scanning must be part of every development workflow.

The ethical boundaries are crucial. The temptation to "just quickly scan" a real website is dangerous - it's illegal and career-ending. Sticking to authorized training apps is the only acceptable approach.

Finding vulnerabilities is only half the battle. Understanding impact, manually verifying exploitability, and explaining remediation requires deeper knowledge than just reading an automated report.

### Connections to Previous Weeks

Week 3's authentication security connects here - SQLi bypasses even strong password hashing. Week 4's malware connects through command injection, which enables malware installation. Web vulnerabilities often serve as initial access vectors.

### Career Relevance

For Security+ certification, vulnerability scanning is a major topic. For the target jobs:
- **FactSet/Starling**: Applications need regular security testing
- **Deloitte**: Consultants must run scans, interpret results, and provide remediation advice

Being able to run vulnerability scans and understand outputs is a demonstrable skill for interviews.

---

## Next Steps

- Practice on other vulnerable apps (DVWA, WebGoat, HackTheBox)
- Learn Burp Suite (industry standard)
- Study OWASP Top 10 in depth
- Develop manual exploitation skills to complement automated scanning
- Try authorized bug bounty programs once confident
