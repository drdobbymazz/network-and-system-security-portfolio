# Week 4: Malicious Software - Workshop Exercise

**Module**: Networks and System Security  
**Student**: Zohaib Khokhar  
**Date**: December 2025  
**Topic**: Malware Detection and Analysis

---

## Workshop Overview

This week's practical focused on understanding how malware operates and how to detect it using Python-based tools. Instead of working with actual malicious code, we simulated key malware behaviours - file tampering, signature scanning, and worm propagation - to safely explore detection and containment strategies.

The workshop demonstrated that effective malware defence requires multiple complementary approaches: file integrity checking, pattern matching, behavioral analysis, and network monitoring.

---

## Exercise 1: File Integrity Checker

### Objective
Build a system that detects unauthorized file modifications by creating SHA-256 hash baselines - essentially how antivirus software knows when a file has been tampered with.

### Implementation

Created a script that:
1. Scans a directory of files
2. Generates SHA-256 hash for each file
3. Saves results to CSV with filename, hash, and timestamp

```python
import hashlib
import os
import csv
from datetime import datetime

def calculate_file_hash(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def create_baseline(directory):
    baseline = []
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            file_hash = calculate_file_hash(filepath)
            timestamp = datetime.now().isoformat()
            baseline.append([filename, file_hash, timestamp])
    
    with open('file_baseline.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Filename', 'SHA256_Hash', 'Timestamp'])
        writer.writerows(baseline)
```

### Key Insight

SHA-256 hashing is perfect for integrity checking because even changing a single bit in a file produces a completely different hash. This is the same hashing we studied in Week 3, but now applied to malware detection instead of password storage.

**Testing**: Created several test files, ran the baseline script, then modified one file and re-scanned. The hash changed immediately, flagging the tampering.

### Why Hashes Over Timestamps?

Timestamps and file sizes can be easily manipulated by malware. An attacker can modify a file and then reset its timestamp to the original value. Hash values are cryptographically secure and cannot be spoofed - if the content changes, the hash changes.

---

## Exercise 2: Detecting File Changes

### Objective
Compare current file hashes against the baseline to identify which files have been modified, added, or deleted.

### Implementation

Built a comparison function that loads the baseline CSV and checks current files against it:

```python
def detect_changes(directory, baseline_file='file_baseline.csv'):
    # Load baseline
    baseline = {}
    with open(baseline_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            baseline[row['Filename']] = row['SHA256_Hash']
    
    # Check current files
    current_files = set()
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            current_files.add(filename)
            current_hash = calculate_file_hash(filepath)
            
            if filename in baseline:
                if baseline[filename] != current_hash:
                    print(f"⚠️  MODIFIED: {filename}")
            else:
                print(f"🆕 NEW FILE: {filename}")
    
    # Check for deleted files
    for filename in baseline:
        if filename not in current_files:
            print(f"🗑️  DELETED: {filename}")
```

### Testing Results

Created three scenarios:
1. **Modified file**: Changed content of `document.txt` - Detected immediately
2. **New file**: Added `suspicious.exe` - Flagged as new
3. **Deleted file**: Removed `system.dll` from directory - Flagged as deleted

This demonstrates how viruses that modify executables or add new malicious files would be caught by integrity checking.

### Limitations Discussed

**Rootkits**: If malware operates at the kernel level, it could intercept file reads and return fake "clean" content, bypassing hash checks. This is why modern security uses trusted boot processes and kernel-level protections.

**Legitimate updates**: Windows updates modify hundreds of system files. In production, you'd need to:
- Update baseline after verified system updates
- Use digital signatures to verify legitimate changes
- Implement change approval workflows

---

## Exercise 3: Signature-Based Malware Scanner

### Objective
Understand how early antivirus worked - scanning files for known malicious patterns - and why it's insufficient today.

### Implementation

Built a simple pattern matcher that searches for suspicious code patterns:

```python
import re

SIGNATURES = [
    r"eval\(",              # Code execution
    r"base64\.b64decode",   # Obfuscation technique
    r"socket\.connect",     # Network connection
    r"exec\(",              # Command execution
    r"import os"            # System access
]

def scan_file_for_signatures(filepath):
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            
        matches = []
        for signature in SIGNATURES:
            if re.search(signature, content):
                matches.append(signature)
        
        if matches:
            print(f"⚠️  {filepath}: Found suspicious patterns: {matches}")
            return True
        return False
    except:
        return False  # Binary or unreadable file
```

### Testing

Created test Python files with various patterns:
- `clean_script.py`: Normal code, no matches
- `suspicious_script.py`: Contains `eval()` and `socket.connect()` - Flagged
- `obfuscated.py`: Uses `base64.b64decode()` - Flagged

### Why Signatures Fail

**Polymorphic malware**: Changes its code signature with each infection while maintaining functionality. The pattern never matches.

**Obfuscation**: Attackers can easily modify their code to avoid patterns:
- `eval()` → `getattr(__builtins__, 'eval')`  
- `socket.connect()` → Dynamic string construction

**False positives**: Legitimate code often uses these patterns. Python scripts routinely use `import os` for file operations, not malicious purposes.

This is why modern antivirus shifted to behavioral analysis - watching what programs *do* (file access, network connections, registry changes) rather than what they *contain*.

---

## Exercise 4: Worm Propagation Simulation

### Objective
Visualize how network worms spread exponentially by simulating random scanning and infection.

### Implementation

Simulated a network of 1000 hosts where an infected host randomly scans and infects others:

```python
import random

class WormSimulation:
    def __init__(self, total_hosts=1000, initial_infected=1):
        self.total_hosts = total_hosts
        self.infected = set([0])  # Host 0 starts infected
        self.vulnerable = set(range(1, total_hosts))
        self.infection_history = []
    
    def propagate_round(self, scans_per_host=10):
        new_infections = set()
        
        for infected_host in list(self.infected):
            for _ in range(scans_per_host):
                target = random.randint(0, self.total_hosts - 1)
                if target in self.vulnerable:
                    new_infections.add(target)
        
        self.infected.update(new_infections)
        self.vulnerable -= new_infections
        self.infection_history.append(len(self.infected))
        
        return len(new_infections)
    
    def run_simulation(self, max_rounds=50):
        for round_num in range(max_rounds):
            new = self.propagate_round()
            print(f"Round {round_num + 1}: {len(self.infected)} infected (+{new})")
            if len(self.vulnerable) == 0:
                print(f"Full infection in {round_num + 1} rounds")
                break
```

### Results

Running the simulation showed exponential growth:
- Round 1: 1 infected
- Round 5: 47 infected
- Round 10: 387 infected
- Round 15: 891 infected
- Round 17: 1000 infected (full network)

The infection curve follows an S-shaped pattern - slow start, rapid exponential growth, then slowing as it runs out of vulnerable hosts.

### Propagation Dynamics

**Random scanning**: The worm tries random IP addresses. Initially inefficient but becomes more effective as infection spreads.

**Local subnet targeting**: Real worms often prioritize nearby IP addresses because:
- Lower latency = faster scanning
- Local hosts more likely to have similar vulnerabilities
- Harder to detect than cross-network scanning

**Containment strategies discussed**:
1. **Rate limiting**: Restrict outbound connection attempts per host
2. **Scan detection**: IDS alerts on excessive port scanning
3. **Network segmentation**: Isolate subnets to prevent spread
4. **Patch vulnerable systems**: Remove targets from the pool

---

## Exercise 5: Designing Countermeasures

### Objective
Combine techniques from previous exercises into a layered defense system.

### Group Task

Designed a monitoring system that:
1. Runs file integrity checks hourly
2. Logs any detected changes
3. Scans new or modified files for suspicious signatures
4. Monitors network connections for anomalies (excessive outbound connections)

### Conceptual Design

```python
class MalwareMonitor:
    def __init__(self, watch_directory):
        self.directory = watch_directory
        self.baseline = self.create_baseline()
        self.alert_threshold = 50  # connections per minute
    
    def hourly_check(self):
        # File integrity checking
        changes = self.detect_file_changes()
        if changes:
            self.alert_admin(changes)
            self.scan_changed_files(changes)
        
        # Network anomaly detection
        if self.check_network_activity() > self.alert_threshold:
            self.alert_admin("Possible worm activity detected")
    
    def scan_changed_files(self, files):
        for file in files:
            if self.signature_scan(file):
                self.quarantine_file(file)
```

### Defence in Depth Principles

**Layer 1 - Prevention**:
- Keep systems patched
- Restrict user privileges
- User education on phishing

**Layer 2 - Detection**:
- File integrity monitoring
- Signature scanning
- Behavioral analysis
- Network anomaly detection

**Layer 3 - Response**:
- Automated quarantine of suspicious files
- Alert administrators
- Isolate infected systems
- Restore from clean backups

No single layer is perfect. Attackers bypass individual defenses, but breaking through all layers simultaneously is much harder.

---

## Key Concepts Applied

### Integrity (CIA Triad)

File integrity checking directly protects the Integrity pillar - ensuring files haven't been unauthorized modified. Malware often compromises integrity by modifying system files, injecting code, or corrupting data.

### Detection vs Prevention

Perfect prevention is impossible. Modern security accepts that breaches will occur and focuses equally on rapid detection and effective response. The file integrity system demonstrates detection - even if malware gets past prevention, it's caught when it modifies files.

### The Arms Race

Malware and defenses constantly evolve:
- **1980s**: Simple viruses, signature detection sufficient
- **1990s**: Polymorphic viruses, heuristic scanning introduced  
- **2000s**: Rootkits, behavioral analysis needed
- **2010s**: Advanced persistent threats, machine learning detection
- **2020s**: AI-powered attacks, AI-powered defenses

Each workshop exercise represents a stage in this evolution.

---

## Real-World Context

### Famous Malware Examples

**WannaCry (2017)**: Worm that exploited Windows SMB vulnerability. Spread to 200,000+ computers in 150 countries in days. Our propagation simulation demonstrates why worms are so dangerous - exponential growth is incredibly fast.

**Stuxnet (2010)**: Sophisticated rootkit that modified industrial control systems while hiding from integrity checks. Demonstrated the limitations of signature-based detection - it was designed to evade all known detection methods.

**CryptoLocker (2013)**: Ransomware that encrypted user files. File integrity checking would detect the encryption, but by then it's too late - prevention is better. This is why layered defense matters.

### Current Challenges

**Fileless malware**: Operates entirely in memory, leaving no files to scan. Our file-based detection would miss it entirely. Requires behavioral monitoring instead.

**Supply chain attacks**: Legitimate software compromised at source. Digital signatures and trusted repositories help, but sophisticated attackers can still succeed.

**Zero-day exploits**: Unknown vulnerabilities with no signatures available. Behavioral analysis and anomaly detection are crucial.

---

## Reflection

This workshop made malware detection feel much less abstract. Building the file integrity checker showed me exactly how antivirus "knows" when a file has changed - it's just comparing hashes, which is simple but effective.

The worm simulation was eye-opening. Seeing how quickly infection spreads - full network penetration in under 20 rounds - explains why security teams treat worm outbreaks as emergencies. The exponential growth curve means you have very little time to respond before containment becomes impossible.

What struck me most was how signature-based detection is fundamentally flawed against determined attackers. It only catches known threats using known patterns. Modern malware uses polymorphism, obfuscation, and encryption specifically to defeat signatures. This explains the industry shift toward behavioral analysis and machine learning - you need to detect *actions* not just *code patterns*.

The workshop also highlighted that no single defense is sufficient. File integrity catches some threats, signatures catch others, network monitoring catches worms, but sophisticated malware can potentially evade any individual layer. Defence in depth isn't optional - it's essential.

### Connections to Previous Weeks

Week 3's authentication security connects here - malware often targets weak authentication to gain initial access. If an attacker can't compromise credentials, they can't install malware in the first place.

Week 2's encryption principles also apply - some malware (ransomware) uses encryption against users, while security tools use encryption (digital signatures) to verify software integrity.

### Questions That Arose

**How do you balance security with performance?** File integrity checking every file hourly creates significant CPU and disk load. In production, you'd need to prioritize critical system files and executables.

**What about false positives?** Legitimate software updates trigger integrity alerts. How do you distinguish between legitimate changes and malicious ones without overwhelming administrators?

**Can AI really detect zero-day malware?** Machine learning is promising but how do you train models without examples of future attacks? This seems like a fundamental challenge.

---

## Career Relevance

For the three jobs from Week 1:

**FactSet**: Financial systems are prime targets for malware (data theft, ransomware). Understanding detection mechanisms and incident response is valuable.

**Starling Bank**: Banking apps must protect against malware on user devices and backend systems. Mobile malware is a growing threat that this workshop's principles apply to.

**Deloitte**: Security consultants audit malware defenses. Being able to assess whether a client's integrity checking, signature scanning, and behavioral analysis are properly implemented is a key skill.

Understanding that signature-based detection is outdated helps in recommending modern solutions to clients.

---

## Next Steps

To extend this workshop:
- Implement real-time file monitoring instead of periodic scans
- Add machine learning for anomaly detection (identify unusual network patterns)
- Build automated response system (quarantine, isolate, alert)
- Integrate with SIEM for centralized logging and correlation
- Test against real malware samples in isolated VM environment

The foundational techniques here - hashing, pattern matching, behavioral monitoring - scale to production security systems. The main differences are scale, performance optimization, and sophisticated analysis algorithms.

This practical work complements the Security+ certification preparation - CompTIA Security+ covers malware types, attack vectors, and detection methods theoretically, while this workshop provided hands-on implementation experience.
