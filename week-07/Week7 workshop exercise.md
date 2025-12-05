# Week 7: Penetration Testing Fundamentals

**Module**: Networks and System Security  
**Student**: Zohaib Khokhar  
**Date**: December 2025  
**Topic**: Introduction to Ethical Hacking and Pen Testing

---

## Workshop Overview

This workshop introduced the fundamentals of penetration testing - authorized security assessments that simulate real-world attacks to identify vulnerabilities before malicious actors exploit them. Using Python, we explored reconnaissance techniques, port scanning, and service enumeration on authorized targets (localhost and public domains with proper permissions).

**Critical principle**: Penetration testing is ONLY legal with explicit written authorization. Unauthorized testing violates the Computer Misuse Act and similar laws worldwide.

---

## What is Penetration Testing?

Penetration testing is essentially authorized hacking. Companies hire pen testers to attack their systems and find vulnerabilities before real attackers do. The key difference between pen testers and malicious hackers is permission - pen testers have written authorization from system owners, document everything they find, and provide recommendations for fixing issues.

The purpose is straightforward: discover and fix security weaknesses proactively rather than waiting for a breach. But it's important to understand that pen testing isn't a magic solution. It supplements broader security strategies like regular patching, continuous monitoring, and user training - it doesn't replace them.

---

## Pen Testing Methodology

Professional penetration tests follow a systematic approach with six main phases. First comes reconnaissance, where you gather information about the target through both passive techniques (like searching public records) and active probing. Then scanning and enumeration identifies live hosts, open ports, and running services. The vulnerability assessment phase finds exploitable weaknesses in those services.

Once vulnerabilities are identified, the exploitation phase attempts to actually breach systems - this is where you try to gain unauthorized access. Post-exploitation involves maintaining that access and potentially pivoting to other systems to see how far an attacker could go. Finally, everything gets documented in a comprehensive report with severity ratings and remediation advice.

This workshop focused on the first two phases - reconnaissance and scanning - because they're the safest and most fundamental techniques. You need to walk before you can run.

When it comes to test types, black box testing gives you minimal information, simulating an external attacker who knows nothing about the internal systems. It's the most realistic for testing how well you defend against outsiders. White box testing is the opposite - full access to source code, architecture diagrams, and credentials. It's the most thorough approach but doesn't test whether your monitoring would actually detect an attack. Grey box testing sits somewhere in between, giving partial information like network diagrams but no credentials.

---

## Exercise 1: WHOIS Domain Lookup

WHOIS lookups are your starting point for passive reconnaissance. They provide public information about domain ownership that anyone can access legally. You can find out when a domain was registered, when it expires, who the registrar is, what nameservers are being used, and sometimes organization details if the owner hasn't enabled privacy protection.

### Implementation

```python
import socket
import requests

def get_domain_info(domain):
    try:
        # Get IP address
        ip = socket.gethostbyname(domain)
        print(f"IP Address: {ip}")
        
        # Get geolocation data via public API
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        if response.status_code == 200:
            data = response.json()
            print(f"Organization: {data.get('org', 'Unknown')}")
            print(f"City: {data.get('city', 'Unknown')}")
            print(f"Country: {data.get('country_name', 'Unknown')}")
        else:
            print("Could not fetch geolocation data.")
    except Exception as e:
        print(f"Error: {e}")

# Test on authorized public domain
get_domain_info("example.com")
```

### Results

```
IP Address: 93.184.216.34
Organization: Edgecast Inc.
City: Norwell
Country: United States
```

Reconnaissance like this reveals useful intelligence without ever directly touching the target system. You learn about the infrastructure provider (is it AWS? Azure? A small hosting company?), geographic location which tells you about data residency and legal jurisdiction, organization details like company size and industry, and network architecture hints like whether multiple IPs suggest load balancing.

The key thing about passive reconnaissance like WHOIS is that it's completely legal. You're just querying public databases that anyone can access. You're not sending packets to the target or attempting any kind of access.

---

## Exercise 2: Black Box vs White Box Testing

### Black Box Reconnaissance

Simulating an external attacker with no inside knowledge. We probe HTTP headers to identify server technology.

```python
import requests

def black_box_recon(url):
    try:
        response = requests.head(url)
        print("Black Box Findings:")
        print(f"Server: {response.headers.get('Server', 'Unknown')}")
        print(f"Content-Type: {response.headers.get('Content-Type', 'Unknown')}")
        print(f"X-Powered-By: {response.headers.get('X-Powered-By', 'Not disclosed')}")
    except Exception as e:
        print(f"Error: {e}")

black_box_recon("http://example.com")
```

### Results

```
Black Box Findings:
Server: ECS (dcb/7EA3)
Content-Type: text/html; charset=UTF-8
X-Powered-By: Not disclosed
```

### White Box Context

If we had white box access, we'd know:
- Exact server version: "Apache 2.4.41"
- Known vulnerabilities: "CVE-2021-44790 (mod_lua RCE)"
- Internal architecture, firewall rules, authentication mechanisms

**Trade-off**: Black box is realistic but time-consuming. White box is thorough but doesn't test detection capabilities.

### Server Header Hiding

Many servers return "Unknown" or generic headers for security. This is **security through obscurity** - helps but doesn't prevent determined attackers who can use other fingerprinting techniques (response timing, error messages, etc.).

---

## Exercise 3: Basic Port Scanning

Port scanning is about figuring out which services are running on a target. Think of ports as numbered doors on a building - each service listens on a specific port. HTTP uses port 80, HTTPS uses 443, SSH uses 22, MySQL uses 3306, and so on. By scanning these ports, you identify what services are accessible and therefore what the attack surface looks like.

### Implementation

```python
import socket

def scan_ports(host, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

host = "127.0.0.1"  # localhost only
ports = [80, 443, 22, 8080, 3306, 5432]
open_ports = scan_ports(host, ports)
print(f"Open ports on {host}: {open_ports}")
```

### Results (Localhost)

```
Open ports on 127.0.0.1: [22, 3306]
```

Found SSH (22) and MySQL (3306) running locally.

### How It Works

The `connect_ex()` method attempts a TCP connection to each port. If the connection succeeds (returns 0), the port is open. If it fails, you get an error code meaning the port is closed or filtered by a firewall. The 1-second timeout prevents the script from hanging on closed ports, though it might miss services that respond slowly.

Port scanning reveals your attack surface - more open services means more potential vulnerabilities to explore. It guides what you investigate next. But it also exposes misconfigurations, like when databases are accidentally exposed to the internet on public IPs when they should only be accessible internally.

---

## Exercise 4: Advanced Scanning with Nmap

Nmap (Network Mapper) is the industry standard for network reconnaissance, and it's far more sophisticated than basic port scanning. Beyond just finding open ports, it can detect service versions, fingerprint operating systems, run vulnerability scans through its scripting engine, and even employ evasion techniques to bypass firewalls and intrusion detection systems.

### Using Nmap via Python

```python
import nmap

def nmap_scan(host, port_range='1-1024'):
    nm = nmap.PortScanner()
    try:
        # -sV flag enables service version detection
        nm.scan(host, port_range, arguments='-sV')
        
        for host in nm.all_hosts():
            print(f"Host: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            
            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                lport = nm[host][proto].keys()
                
                for port in sorted(lport):
                    service = nm[host][proto][port]
                    print(f"Port: {port}\t"
                          f"State: {service['state']}\t"
                          f"Service: {service.get('name', 'unknown')} "
                          f"{service.get('version', '')}")
    except Exception as e:
        print(f"Error: {e}")

# Scan localhost (always authorized)
nmap_scan('127.0.0.1', '1-100')
```

### Results

```
Host: 127.0.0.1 (localhost)
State: up
Protocol: tcp
Port: 22    State: open    Service: ssh OpenSSH 8.2p1
Port: 80    State: open    Service: http nginx 1.18.0
Port: 3306  State: open    Service: mysql MySQL 8.0.27
```

### Service Version Detection

What makes Nmap powerful is that it doesn't just tell you a port is open - it identifies the exact software and version number running on that port. For example, finding OpenSSH 8.2p1, nginx 1.18.0, and MySQL 8.0.27. This is crucial because you can then cross-reference these specific versions against vulnerability databases like CVE to find known exploits.

For instance, if you discover "OpenSSH 8.2p1" is running, you can search the CVE database and find CVE-2020-15778, a privilege escalation vulnerability affecting that exact version. Without version detection, you'd just know SSH is running but have no idea if it's vulnerable.

The Nmap Scripting Engine (NSE) extends this even further with Lua scripts that automate vulnerability detection, advanced service enumeration, brute force authentication attempts, and exploit verification. Running `--script vuln` executes all the built-in vulnerability detection scripts against your target.

---

## Penetration Testing Tools Ecosystem

The pen testing world has tools specialized for each phase. For reconnaissance, you've got Nmap for network scanning, Shodan which is essentially a search engine for internet-connected devices, theHarvester for gathering emails and subdomains through open source intelligence, and Maltego for visual link analysis that maps relationships between entities.

Vulnerability assessment tools include Nessus (commercial and widely used), OpenVAS (the open-source alternative), and Nikto for scanning web servers specifically. When you move into exploitation, Metasploit is the framework everyone knows - it's got thousands of exploits ready to use. Burp Suite dominates web application testing, and SQLMap automates SQL injection attacks.

Post-exploitation tools help maintain access once you're in. Mimikatz extracts credentials from Windows systems, and Cobalt Strike provides advanced threat emulation capabilities that red teams use.

This workshop only scratched the surface with reconnaissance and scanning, which is appropriate because you need solid fundamentals before jumping into exploitation tools.

---

## Ethical and Legal Boundaries

### Why Authorization is Critical

This cannot be stressed enough: unauthorized access is illegal. Period. The Computer Misuse Act 1990 in the UK, the Computer Fraud and Abuse Act in the USA, and similar laws worldwide criminalize unauthorized system access. Even "harmless" port scanning without permission is illegal. There have been actual court cases where security researchers were prosecuted for unauthorized testing, even when they were trying to help by discovering critical vulnerabilities.

The case of Andrew "Weev" Auernheimer in 2013 is a perfect example. He discovered an AT&T vulnerability by simply iterating through URL parameters. He didn't exploit it, didn't access sensitive data, didn't cause any damage - just found a flaw and reported it. He was still sentenced to prison because the access was unauthorized. That's how seriously courts take this.

### Where You Can Legally Practice

If you want to practice penetration testing, there are legitimate options. Your own localhost is always fair game - it's your machine. Online platforms like HackTheBox, TryHackMe, and OverTheWire provide deliberately vulnerable environments specifically designed for learning. You can also install DVWA (Damn Vulnerable Web Application) locally for testing.

Bug bounty programs are another legal avenue. Companies like Google, Facebook, and Microsoft explicitly authorize security testing on their platforms and actually pay you for valid findings. It's the perfect way to practice on real systems legally.

### Professional Penetration Testing

Real professional pen tests require extensive documentation. You need written authorization in the form of a statement of work, explicit scope definition detailing exactly which systems and techniques are allowed, defined time windows for when testing can occur, a communication plan with emergency contacts in case something goes wrong, and professional liability insurance. Without all of this, you're just hacking without permission, regardless of your intentions.

---

## Practical Insights

### What Surprised Me

How much information is publicly available without any hacking. WHOIS lookups, DNS records, HTTP headers, and certificate transparency logs reveal extensive details about infrastructure - all legally accessible.

This explains why "reconnaissance" is a major phase in pen testing. Attackers spend significant time gathering intelligence before attempting exploitation.

### Limitations of Port Scanning

**Firewalls**: Many organizations use firewalls that silently drop packets, making ports appear closed when they're actually filtered. Advanced Nmap techniques (-sA, -sF, -sX) attempt to bypass these.

**IDS/IPS**: Intrusion detection systems flag aggressive scanning. Professional pen testers use slow, stealthy scans to avoid triggering alerts.

**Dynamic ports**: Services don't always run on standard ports. SSH might be on 2222 instead of 22 to reduce automated attacks.

### Nmap vs Basic Scanning

Our basic Python port scanner took ~6 seconds to scan 6 ports. Nmap scanned 100 ports with service detection in ~3 seconds. Why?
- Optimized C code vs interpreted Python
- Parallel scanning vs sequential
- Intelligent timeout algorithms
- Years of development and optimization

**Lesson**: Use professional tools for real work, write custom scripts for specific use cases.

---

## Connections to Previous Work

### Week 4 - Malware Detection

Week 4 covered defensive techniques (file integrity, signatures). Week 7 shows the offensive perspective - how attackers identify targets and vulnerabilities. Understanding both attack and defense creates complete security picture.

### Week 5 - Web Security

Week 5's Wapiti scanning is specialized pen testing for web applications. Week 7 covers broader network-level reconnaissance that identifies web servers before targeted web testing.

### Week 6 - Binary Analysis

Port scanning reveals services. Binary analysis (Week 6) examines those services for vulnerabilities. Combined: find service (Week 7) → analyze binary (Week 6) → exploit weakness.

---

## Career Relevance

### FactSet

Financial platforms undergo regular pen testing to maintain regulatory compliance (SOC 2, ISO 27001). Understanding pen testing methodology helps security teams interpret external assessment reports and remediate findings.

### Starling Bank

Banking regulations require penetration testing. Security teams must understand attacker techniques to build effective defenses. This workshop's techniques (reconnaissance, port scanning) are exactly what bank security teams defend against daily.

### Deloitte

Security consultants conduct pen tests for clients. The methodology covered here (reconnaissance → scanning → enumeration → exploitation → reporting) is the standard approach. Understanding fundamentals is essential before using advanced tools like Metasploit.

---

## Reflection

This workshop made "ethical hacking" concrete. Previously, penetration testing seemed like a specialized skill requiring deep networking knowledge. Seeing how basic Python socket programming enables port scanning demystified the process - it's systematic methodology applied with the right tools.

The ethical emphasis was crucial. The ease of scanning makes it tempting to "just quickly check" a website, but the legal consequences are severe. The workshop's repeated warnings about authorization reinforced that penetration testing isn't hacking with permission - it's a professional service requiring contracts, insurance, and clear boundaries.

What stood out was how much reconnaissance happens before any exploitation attempts. In movies, hackers immediately start typing frantically. In reality, pen testers spend days gathering information about targets, mapping networks, and identifying services before attempting a single exploit. The reconnaissance phase is the foundation for everything that follows.

For Security+ certification (Week 1 action plan), penetration testing methodology is a major exam topic. Understanding the phases, tools (Nmap, Metasploit), and ethical considerations provides practical knowledge beyond theory.

---

## Next Steps

To build on this workshop:
- Complete HackTheBox challenges (authorized testing environment)
- Study Metasploit for exploitation phase
- Learn Burp Suite for web app pen testing
- Practice Nmap scripting engine (NSE)
- Explore OSINT (Open Source Intelligence) techniques
- Consider OSCP (Offensive Security Certified Professional) certification

The foundational skills from this workshop - reconnaissance, port scanning, service enumeration - are prerequisites for advanced penetration testing. The next stage is moving from scanning (passive) to exploitation (active).

This workshop completed a comprehensive security testing toolkit across the module: vulnerability scanning (Week 5), malware analysis (Week 6), and penetration testing (Week 7). Together, these provide both offensive and defensive security perspectives.
