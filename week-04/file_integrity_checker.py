#!/usr/bin/env python3
"""
File Integrity Checker
Week 4 - Malicious Software Workshop
Creates SHA-256 baseline of files in a directory
"""

import hashlib
import os
import csv
from datetime import datetime

def calculate_hash(filepath):
    """Calculate SHA-256 hash of a file"""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def create_baseline(directory, output_file='file_baseline.csv'):
    """Create baseline CSV of file hashes"""
    baseline = []
    
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if os.path.isfile(filepath):
            file_hash = calculate_hash(filepath)
            timestamp = datetime.now().isoformat()
            baseline.append([filename, file_hash, timestamp])
            print(f"✓ Hashed: {filename}")
    
    # Save to CSV
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Filename', 'SHA256_Hash', 'Timestamp'])
        writer.writerows(baseline)
    
    print(f"\n✅ Baseline created: {output_file} ({len(baseline)} files)")

if __name__ == "__main__":
    # Change this to your target directory
    target_dir = "./test_files"
    create_baseline(target_dir)
