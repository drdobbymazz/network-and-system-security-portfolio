# Networks and System Security Portfolio

**Student**: Zohaib Khokhar  
**Student Number**: 33828293
**Institution**: Goldsmiths, University of London  
**Module**: Networks and System Security  
**Academic Year**: 2025/26  

---

## About This Portfolio

This portfolio documents my practical work and learning journey through the Networks and System Security module. Each week covers different security topics with hands-on exercises, technical implementations, and reflections on how these skills apply to real-world cybersecurity careers.

The portfolio demonstrates my understanding of security fundamentals, practical implementation skills, and ability to critically analyze security concepts, all essential for roles in cybersecurity, software engineering, and security consulting.

---

## Portfolio Structure

```
networks-system-security-portfolio/
├── README.md (this file)
├── Week-01/ Career Research & Skills Gap Analysis
├── Week-02/ Cryptography & Secure Communication
├── Week-03/ Authentication & Access Control
├── Week-04/ Malware Detection & Analysis
├── Week-05/ Web Application Security
├── Week-06/ Binary Analysis & Static Malware Analysis
├── Week-07/ Penetration Testing Fundamentals
└── Week-09/ Generative AI Security
```

Each week contains:
- **README.md**: Workshop writeup with technical explanations and reflections
- **code/**: Python scripts, examples, and implementations
- Supporting files (test data, results, documentation)

---

## Weekly Breakdown

### [Week 1: Career Research & Skills Gap Analysis](Week-01/)

**Focus**: Cybersecurity job market analysis and career preparation

Researched three graduate roles in cybersecurity (FactSet, Starling Bank, Deloitte) and conducted comprehensive skills gap analysis. Identified critical gaps (security tools, cloud platforms, certifications) and created 12-week action plan prioritizing CompTIA Security+, hands-on security lab work, and Azure cloud fundamentals.

**Key Skills**: Career planning, self-assessment, security certification roadmap

---

### [Week 2: Cryptography & Secure Communication](Week-02/)

**Focus**: RSA encryption and secure socket programming

Implemented hybrid encryption system combining RSA (for key exchange) and AES (for data encryption). Built client-server application demonstrating how HTTPS and secure messaging apps protect data in transit.

**Technical Implementation**:
- RSA key pair generation (2048-bit)
- AES-256 encryption with random IVs
- TCP socket programming
- Secure key exchange using OAEP padding

**Key Skills**: Cryptography, network programming, secure communications

---

### [Week 3: Authentication & Access Control](Week-03/)

**Focus**: Password security, hashing, and two-factor authentication

Built complete authentication system demonstrating industry-standard security practices. Compared weak hashing (MD5, SHA-256) against secure bcrypt, implemented TOTP-based 2FA, and simulated brute-force attacks to show why proper hashing matters.

**Technical Implementation**:
- Password strength analyzer
- Hashing algorithm comparison (MD5, SHA-256, bcrypt)
- TOTP two-factor authentication with QR codes
- Brute-force attack simulation
- Integrated authentication system

**Key Skills**: Authentication security, cryptographic hashing, 2FA implementation

---

### [Week 4: Malware Detection & Analysis](Week-04/)

**Focus**: Static malware analysis and detection techniques

Developed malware detection tools using file integrity checking, signature-based scanning, and behavioral analysis. Simulated worm propagation to understand how malware spreads across networks.

**Technical Implementation**:
- SHA-256 file integrity checker with baseline comparison
- Signature-based malware scanner (pattern matching)
- Network worm propagation simulator
- Change detection system

**Key Skills**: Malware analysis, file integrity monitoring, threat detection

---

### [Week 5: Web Application Security](Week-05/)

**Focus**: Automated vulnerability scanning with Wapiti

Used Wapiti to scan deliberately vulnerable web applications (Google Gruyere, OWASP Juice Shop), identifying common vulnerabilities like XSS, SQL injection, and file inclusion. Built automated scanning and reporting tools.

**Technical Implementation**:
- Automated Wapiti scanner for authorized targets
- Vulnerability report parser
- XSS, SQLi, file inclusion, and command injection testing

**Key Skills**: Web security, vulnerability scanning, penetration testing methodology

**Code**: [Week-05/code/](Week-05/code/)

---

### [Week 6: Binary Analysis & Static Malware Analysis](Week-06/)

**Focus**: PE file analysis and static triage workflow

Analyzed Windows executables using Python to extract IOCs (Indicators of Compromise). Implemented complete static malware analysis workflow: file hashing, string extraction, PE header inspection, and YARA rule matching.

**Technical Implementation**:
- Multi-algorithm file hashing (MD5, SHA1, SHA256)
- String extraction from binaries
- PE header analysis with `pefile`
- YARA rule writing and matching
- Integrated triage workflow

**Key Skills**: Binary analysis, malware triage, YARA rules, forensic analysis

---

### [Week 7: Penetration Testing Fundamentals](Week-07/)

**Focus**: Ethical hacking and penetration testing methodology

Explored reconnaissance and scanning phases of penetration testing. Implemented WHOIS lookups, HTTP header analysis, port scanning, and service enumeration using both basic Python and professional tools like Nmap.

**Technical Implementation**:
- WHOIS domain reconnaissance
- Black box vs white box testing demonstrations
- TCP port scanner
- Nmap integration for service version detection

**Key Skills**: Penetration testing, network reconnaissance, ethical hacking

---

### [Week 9: Generative AI Security](Week-09/)

**Focus**: Security vulnerabilities in Large Language Models (LLMs)

Deployed local language models using Ollama and conducted red-teaming exercises to identify AI-specific vulnerabilities. Tested prompt injection, data poisoning, model inversion, and extraction attacks across multiple model sizes.

**Technical Implementation**:
- Local LLM deployment with Ollama (smollm2, llama3.2, mistral)
- Prompt injection testing (instruction override attempts)
- Data poisoning simulation (introducing false information)
- Model inversion attacks (extracting memorized data)
- Model extraction simulation (systematic query collection)

**Key Skills**: AI security, red-teaming, adversarial testing, emerging threat analysis

**Important**: All testing conducted on authorized targets only (localhost, public domains, training platforms). Emphasized legal and ethical boundaries throughout.

---

## Technical Skills Demonstrated

### Programming & Development
- Python 3 (primary language throughout portfolio)
- Network programming (sockets, TCP/IP)
- Cryptographic libraries (hashlib, pycryptodome)
- Web frameworks (Flask for testing)
- API integration (requests, web scraping)

### Security Tools & Technologies
- **Cryptography**: RSA, AES, bcrypt, TOTP
- **Malware Analysis**: pefile, YARA, hashlib
- **Web Security**: Wapiti, vulnerability scanning
- **Penetration Testing**: Nmap, port scanning, reconnaissance
- **Authentication**: 2FA, secure password hashing

### Security Concepts
- CIA Triad (Confidentiality, Integrity, Availability)
- Defense in depth
- Authentication & authorization
- Cryptographic principles
- Threat modeling
- Vulnerability assessment
- Static and dynamic analysis
- Penetration testing methodology

---

## Career Connections

Throughout this portfolio, I've explicitly connected technical skills to three target graduate roles:

**FactSet - Software Engineer I**
- Python programming for security tools
- Understanding of encryption and secure communications
- Data protection and integrity verification

**Starling Bank - Graduate Cyber Security Analyst**
- Authentication security (critical for banking)
- Vulnerability scanning and remediation
- Threat detection and incident response
- Regulatory compliance considerations

**Deloitte - Cyber Security Analyst Graduate Programme**
- Penetration testing methodology
- Security assessment and reporting
- Client-facing security consultation skills
- Broad security knowledge across multiple domains

Each week's reflection section explicitly discusses how the skills learned apply to these roles and the broader cybersecurity job market.

---

## Learning Outcomes Achieved

By completing this portfolio, I have demonstrated:

1. **Understanding of security fundamentals**: From cryptography to authentication to network security
2. **Practical implementation skills**: Built working security tools and systems using Python
3. **Analytical thinking**: Reflected critically on security trade-offs, limitations, and real-world applications
4. **Ethical awareness**: Consistently emphasized legal boundaries and responsible security practices
5. **Career readiness**: Connected technical skills to professional cybersecurity roles

---

## Reflections on Learning Journey

### What Surprised Me

The accessibility of security tools was unexpected. Building a port scanner, implementing encryption, or creating a malware detector isn't as complex as I initially thought, it's just about understanding the principles and applying them systematically. This demystified "hacking" and showed it's methodical problem-solving rather than mysterious magic.

### Most Valuable Skills Gained

Practical cryptography implementation (Week 2) gave me confidence that I can build secure systems, not just understand them theoretically. Authentication security (Week 3) is universally applicable as every application needs secure login. Penetration testing methodology (Week 7) provided a systematic framework for thinking like an attacker, which paradoxically makes you a better defender.

### Connections Between Weeks

The portfolio builds progressively. Week 2's encryption protects data. Week 3's authentication controls who accesses it. Week 4's malware detection identifies threats. Week 5 finds vulnerabilities in web apps. Week 6 analyzes suspicious files. Week 7 ties it together with systematic penetration testing.

### Challenges Overcome

Understanding why certain security measures exist (like bcrypt's intentional slowness) required shifting from "faster is better" to "appropriate for purpose." Balancing security with usability is a constant challenge that doesn't have perfect answers, it's about informed trade-offs.

### Career Preparedness

This portfolio demonstrates skills that directly map to security job requirements: vulnerability assessment, secure coding, authentication implementation, threat analysis, and penetration testing. More importantly, it shows I can learn independently, document my work professionally, and think critically about security trade-offs.

---

## Next Steps

Building on this foundation:

1. **CompTIA Security+**: Pursue certification (from Week 1 action plan)
2. **Hands-on labs**: Complete TryHackMe and HackTheBox challenges
3. **Cloud security**: Deploy projects to Azure with security best practices
4. **Advanced tools**: Deep dive into Burp Suite, Metasploit
5. **Real-world practice**: Participate in bug bounty programs (authorized testing)
6. **Continuous learning**: Stay current with emerging threats and defenses

---

## Ethical Statement

All security testing and analysis in this portfolio was conducted:
- On systems I own (localhost)
- On deliberately vulnerable training applications (Google Gruyere, OWASP Juice Shop)
- Within authorized testing environments (HackTheBox, TryHackMe)
- With full understanding of legal boundaries and ethical responsibilities

**I will never conduct unauthorized security testing.** The Computer Misuse Act and similar laws worldwide criminalize unauthorized access, and I am committed to practicing security ethically and legally.

---

## Technical Notes

### Running the Code

All Python scripts use Python 3.8+ and standard libraries where possible. External dependencies are documented in each week's code folder.

**Common requirements**:
```bash
# Cryptography
pip install pycryptodome pyotp qrcode

# Malware Analysis  
pip install pefile yara-python

# Web Security
pip install wapiti3 beautifulsoup4

# Penetration Testing
pip install python-nmap requests
```

### Repository Organization

Each week follows consistent structure:
```
Week-XX/
├── README.md           # Main writeup
└── code/
    ├── README.md       # Code documentation
    ├── script1.py      # Implementation
    ├── script2.py
    └── examples/       # Test data, results
```

---

## Contact & Links

**GitHub**: drdobbymazz    
**Email**: zkhok001@gold.ac.uk

---

## Acknowledgments

This portfolio was completed as part of the Networks and System Security module at Goldsmiths, University of London. Thanks to the teaching staff for providing engaging, practical workshops that built real-world security skills.


---

**Last Updated**: December 2025  
**Module Code**: IS53077A  
**Institution**: Goldsmiths, University of London
