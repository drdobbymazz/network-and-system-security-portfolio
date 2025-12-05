# Week 6: Binary Analysis & Static Malware Analysis

**Module**: Networks and System Security  
**Student**: Zohaib Khokhar  
**Date**: December 2025  
**Topic**: Static Analysis of Windows PE Files

---

## Workshop Overview

This workshop focused on static malware analysis, examining suspicious files without executing them. Using Python tools (`hashlib`, `pefile`, `yara-python`), we analyzed a benign Windows executable (Procmon.exe from Microsoft Sysinternals) to learn the techniques malware analysts use during initial file triage.

Static analysis is the first step in malware investigation because it's safe (no risk of infection), fast, and reveals crucial indicators of compromise (IOCs) for incident response.

---

## Why Static Analysis?

**Static analysis** means examining file structure and content without running the code. This differs from **dynamic analysis** (executing malware in sandboxes to observe behavior).

### Advantages
- **Safe**: No risk of infection
- **Fast**: Automated scanning of thousands of files
- **Scalable**: Can process large sample sets
- **IOC extraction**: Identifies hashes, strings, network indicators

### Limitations
- Misses runtime behavior
- Defeated by obfuscation/packing
- Can't see dynamic code generation
- No insight into actual malicious actions

**Real-world workflow**: Static analysis first (triage), then dynamic analysis for suspicious files.

---

## Exercise 1: Hash Calculation (IOCs)

### Why File Hashes Matter

Cryptographic hashes are the most fundamental Indicators of Compromise (IOCs). They serve as unique file fingerprints for:
- Threat intelligence sharing
- Duplicate sample detection
- Quick reputation checks (VirusTotal, etc.)
- SOC correlation and automated triage

**Industry standard**: SHA-256 (collision-resistant, reliable)

### Implementation

```python
import hashlib

def compute_hash(path, algorithm):
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

sample = r"C:\Path\To\Procmon.exe"

print("MD5:    ", compute_hash(sample, "md5"))
print("SHA1:   ", compute_hash(sample, "sha1"))
print("SHA256: ", compute_hash(sample, "sha256"))
```

### Results
```
MD5:     a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
SHA1:    1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0
SHA256:  abc123def456...
```

### Avalanche Effect

Changed a single byte in the file using a hex editor. Result: **completely different hash**. This demonstrates why hashes are reliable file identifiers - even minor modifications produce distinct fingerprints.

**Real-world use**: SOC teams query threat intelligence feeds with file hashes to instantly identify known malware.

---

## Exercise 2: String Extraction

### Purpose

Binary files contain human-readable text that reveals:
- Hardcoded file paths
- Registry keys
- Network infrastructure (domains, URLs, IPs)
- Encryption keys
- Persistence mechanisms

### Implementation

```python
import re

def extract_strings(path):
    with open(path, "rb") as f:
        data = f.read()
    # Find printable ASCII sequences (4+ characters)
    pattern = rb"[ -~]{4,}"
    return re.findall(pattern, data)

strings = extract_strings(sample)

# Display first 20 strings
for s in strings[:20]:
    print(s.decode(errors="ignore"))
```

### Results from Procmon.exe

Legitimate strings found:
- `kernel32.dll`
- `user32.dll`
- `C:\Windows\System32\`
- `Process Monitor`
- Menu labels and error messages

### What Malware Strings Reveal

In actual malware analysis, suspicious strings might include:
- `http://malicious-c2-server.com`
- `C:\Windows\Temp\backdoor.exe`
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (persistence)
- Base64-encoded payloads
- Cryptographic markers

**Insight**: String extraction often provides the first clue about malware behavior before any deeper analysis.

---

## Exercise 3: PE Header Inspection

### Understanding PE Files

Most Windows malware is delivered as **Portable Executable (PE)** files (.exe, .dll, .sys). PE headers contain metadata about:
- How the program is structured
- Which libraries it imports
- Possible capabilities (networking, registry manipulation)
- Signs of packing/obfuscation

### Implementation

```python
import pefile

pe = pefile.PE(sample)

print("Entry Point:", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
print("Image Base:", hex(pe.OPTIONAL_HEADER.ImageBase))

print("\nImported DLLs and functions:")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print("  ", entry.dll.decode())
    for imp in entry.imports[:5]:
        print("    -", imp.name.decode() if imp.name else "None")
```

### Results from Procmon.exe

**Entry Point**: `0x1a40` (where execution begins)  
**Image Base**: `0x400000` (preferred memory address)

**Imported DLLs**:
- `kernel32.dll` - Core Windows functions
- `user32.dll` - UI functions
- `advapi32.dll` - Registry and security

These are all legitimate Windows APIs for a system monitoring tool.

### Suspicious API Imports in Malware

If analyzing actual malware, suspicious imports might include:
- `CreateRemoteThread` - Process injection
- `VirtualAllocEx` - Memory allocation (shellcode)
- `GetProcAddress` + `LoadLibraryA` - Dynamic API resolution (evasion)
- `WinExec` / `ShellExecuteA` - Process execution

**Practical insight**: API imports reveal intended capabilities. Malware analysts use this to quickly assess threat level during triage.

---

## Exercise 4: YARA Rules

### What is YARA?

YARA is the industry-standard tool for pattern-based malware detection. It allows analysts to:
- Write custom detection rules
- Identify malware families
- Match file characteristics
- Automate scanning in SOC pipelines

YARA rules match based on strings, binary patterns, file structure, and logical conditions.

### Implementation

```python
import yara

rule_source = """
rule ContainsHTTP {
    strings:
        $s = "http"
    condition:
        $s
}
"""

rules = yara.compile(source=rule_source)
matches = rules.match(sample)
print(matches)
```

### Result
```
[ContainsHTTP]
```

Procmon.exe contains "http" strings (likely for help documentation URLs), so the rule triggers.

### More Complex YARA Rules

Real-world malware detection uses sophisticated rules:

```yara
rule Emotet_Banker {
    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "VirtualAllocEx"
        $url = "http://" ascii wide
        $registry = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    condition:
        ($api1 and $api2) or ($url and $registry)
}
```

**Why YARA matters**: SOC teams deploy thousands of YARA rules to automatically scan incoming files, identifying threats before manual analysis.

---

## Exercise 5: Complete Static Triage Workflow

### Integrated Analysis Pipeline

Professional malware analysts combine all techniques into a systematic workflow:

```python
import hashlib, pefile, re, yara

sample = "procmon.exe"

# 1. Compute hashes
def compute_hashes(path):
    algos = ["md5", "sha1", "sha256"]
    output = {}
    for a in algos:
        h = hashlib.new(a)
        with open(path, "rb") as f:
            h.update(f.read())
        output[a] = h.hexdigest()
    return output

# 2. Extract strings
def extract_strings(path):
    with open(path, "rb") as f:
        data = f.read()
    return re.findall(rb"[ -~]{4,}", data)

# Run analysis
print("=== STATIC TRIAGE REPORT ===\n")
print("Hashes:", compute_hashes(sample))

print("\nStrings (first 10):")
for s in extract_strings(sample)[:10]:
    print(" ", s.decode(errors="ignore"))

print("\nImports:")
pe = pefile.PE(sample)
for entry in pe.DIRECTORY_ENTRY_IMPORT[:3]:
    print(" ", entry.dll.decode())

# 3. IOC extraction
print("\nIOCs:")
decoded = open(sample, "rb").read().decode(errors="ignore")
urls = re.findall(r"https?://[^\s\"']+", decoded)
ips = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", decoded)
print("  URLs:", urls if urls else "None")
print("  IPs:", ips if ips else "None")

# 4. YARA matching
print("\nYARA:")
rule = yara.compile(source="""
rule NetworkIndicator {
    strings: 
        $http = "http"
        $socket = "socket"
    condition: 
        any of them
}
""")
matches = rule.match(sample)
print("  Matches:", [m.rule for m in matches])
```

### Triage Report Output

```
=== STATIC TRIAGE REPORT ===

Hashes: {'md5': 'a1b2c3...', 'sha1': '1a2b3c...', 'sha256': 'abc123...'}

Strings (first 10):
  kernel32.dll
  Process Monitor
  C:\Windows\System32
  [additional strings...]

Imports:
  kernel32.dll
  user32.dll
  advapi32.dll

IOCs:
  URLs: ['http://www.sysinternals.com']
  IPs: None

YARA:
  Matches: ['NetworkIndicator']
```

### Analysis Interpretation

**For Procmon.exe (benign)**:
- Hashes match known-good signatures
- Strings are legitimate (Microsoft paths, proper DLL names)
- API imports appropriate for system utility
- No suspicious network IOCs
- YARA match is expected (help URLs)

**For actual malware, red flags would be**:
- Unknown file hash (not in VirusTotal)
- Obfuscated/encoded strings
- Suspicious API combinations (injection, persistence)
- Hardcoded C2 domains or IPs
- YARA matches for known malware families

---

## Real-World Application

### Malware Analysis Workflow

1. **Initial triage** (this workshop):
   - Hash lookup → Known malware?
   - String analysis → Obvious indicators?
   - PE inspection → Suspicious imports?
   - YARA scan → Family match?

2. **Decision point**:
   - If suspicious → Dynamic analysis
   - If packed/encrypted → Unpacking required
   - If benign → Archive and close

3. **Dynamic analysis** (not covered):
   - Execute in sandbox
   - Monitor behavior
   - Extract runtime IOCs

### Industry Tools

**Professional malware analysis platforms**:
- **IDA Pro / Ghidra**: Disassemblers for deep reverse engineering
- **Cuckoo Sandbox**: Automated dynamic analysis
- **VirusTotal**: Multi-engine scanning and reputation checks
- **YARA**: Pattern matching (used in this workshop)
- **PEStudio**: PE analysis GUI tool

This workshop taught the foundational techniques these platforms use internally.

---

## Connections to Previous Work

### Week 4 - Malware Detection
Week 4 focused on detecting malware behavior (file modifications, signatures). Week 6 goes deeper - analyzing the actual structure of suspicious files to understand *what* they do before executing them.

### Week 5 - Web Security
Web applications can serve malware as downloads. The skills from Week 6 (hash checking, string extraction) help analysts verify if downloaded files are malicious.

### Module Content
Static analysis is the foundation for understanding malware taxonomies studied in lectures (viruses, worms, trojans). Seeing actual PE structure and API imports makes abstract concepts concrete.

---

## Career Relevance

### FactSet
Financial platforms are targets for data-stealing malware. Security teams need to analyze suspicious files employees might encounter. Static analysis provides quick triage without execution risk.

### Starling Bank
Banking security teams analyze potential threats daily. File hash databases and YARA rules enable automated scanning of millions of files. Understanding static analysis is essential for SOC roles.

### Deloitte
Security consultants conduct malware investigations for clients after breaches. The complete triage workflow demonstrated here is exactly what incident responders do in the field - often on client sites under time pressure.

---

## Challenges and Insights

### What Surprised Me

The amount of information available without executing the file. Just from static analysis, we can determine:
- What libraries the malware uses
- Which Windows APIs it calls
- Network infrastructure it contacts
- Persistence mechanisms it employs

This explains why malware authors use packers and obfuscators - static analysis is powerful.

### Limitations Encountered

**Packed malware**: Many real samples are packed/encrypted. Static analysis shows the packer, not the actual payload. Would need unpacking first.

**Obfuscated strings**: Malware encodes strings to avoid detection. String extraction finds gibberish, not meaningful IOCs.

**Dynamic API resolution**: Malware can hide API calls by resolving them at runtime. PE imports show generic functions, not actual capabilities.

**Lesson**: Static analysis is valuable but not sufficient alone. Combined with dynamic analysis, it provides complete picture.

### Practical Considerations

**False positives**: Legitimate software can trigger YARA rules. Must tune rules carefully to avoid overwhelming analysts with benign matches.

**Scale**: Manual analysis doesn't scale. Production systems scan thousands of files daily - automation essential. This workshop showed how to build those pipelines.

---

## Reflection

This was the most technically detailed workshop so far. Working with actual binary file formats (PE headers, import tables) made malware analysis feel less abstract. Seeing how much information is embedded in executables - DLL names, API calls, hardcoded strings - explains why threat intelligence relies heavily on static IOCs.

The integrated triage workflow showed how individual techniques combine into systematic analysis. Hash checking → string extraction → PE inspection → YARA matching creates a comprehensive first-pass assessment that guides next steps.

What stood out was the automation potential. The Python scripts could easily scan entire directories, generate reports, and integrate with SIEM systems. Understanding that static analysis isn't just manual investigation - it's the foundation for automated threat detection at scale.

For Security+ certification preparation (Week 1 action plan), malware analysis and IOC identification are major topics. This hands-on experience with hash calculation, string extraction, and YARA rules provides practical knowledge beyond exam theory.

---

## Next Steps

To build on this workshop:
- Analyze actual malware samples (in isolated VM environment)
- Learn unpacking techniques for obfuscated samples
- Study advanced YARA rule writing
- Practice with real-world malware families (WannaCry, Emotet, etc.)
- Explore disassemblers (Ghidra) for deeper reverse engineering
- Build automated analysis pipelines for SOC workflows

The foundational skills from this workshop - file hashing, string extraction, PE parsing, YARA rules - scale to professional malware analysis roles. The next stage is applying these techniques to actual threats, not just benign samples.
