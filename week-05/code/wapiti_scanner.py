#!/usr/bin/env python3
"""
Wapiti Scanner & Report Parser
Week 5 - Web Security Workshop
Automates vulnerability scanning and result analysis
"""

import subprocess
import os
from datetime import datetime

# Only scan authorized targets
AUTHORIZED_TARGETS = {
    "gruyere": "https://google-gruyere.appspot.com/YOUR_ID/",
    "juice_shop": "https://juice-shop.herokuapp.com"
}

def run_scan(target_name, url):
    """Run Wapiti scan on target"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output = f"{target_name}_{timestamp}.html"
    
    print(f"🔍 Scanning {target_name}...")
    print(f"   Target: {url}\n")
    
    cmd = ["wapiti", "-u", url, "-o", output, "--format", "html"]
    
    try:
        subprocess.run(cmd, timeout=1800)
        print(f"✅ Scan complete: {output}\n")
        return output
    except FileNotFoundError:
        print("❌ Wapiti not found. Install: pip install wapiti3")
        return None
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def scan_all():
    """Scan all authorized targets"""
    print("=" * 50)
    print("AUTOMATED VULNERABILITY SCANNER")
    print("⚠️  Only scanning authorized training targets")
    print("=" * 50 + "\n")
    
    for name, url in AUTHORIZED_TARGETS.items():
        if "YOUR_ID" in url:
            print(f"⚠️  Skipping {name} - update URL first\n")
            continue
        run_scan(name, url)

if __name__ == "__main__":
    scan_all()
