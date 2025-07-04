#!/usr/bin/env python3

import sys
import os
import csv
import json

if len(sys.argv) != 4:
    print("Usage: python3 extract_secrets_to_csv2.py <trufflehog_json> <semgrep_json> <output_csv_file>")
    sys.exit(1)

trufflehog_file = sys.argv[1]
semgrep_file = sys.argv[2]
output_csv = sys.argv[3]

headers = [
    "Secret Type", "File Path", "Line Number", "Secret Value",
    "Detector/Tool", "Severity", "Description", "Rule URL"
]

# For deduplication
seen = set()

def normalize_key(*args):
    return "||".join([str(a).strip().lower() for a in args if a])

def process_semgrep(semgrep_path):
    results = []
    try:
        with open(semgrep_path, 'r') as f:
            data = json.load(f)
            for item in data.get("results", []):
                key = normalize_key("semgrep", item.get("path"), item.get("start", {}).get("line"), item.get("extra", {}).get("message"))
                if key in seen:
                    continue
                seen.add(key)
                results.append([
                    item.get("extra", {}).get("message", ""),
                    item.get("path", ""),
                    item.get("start", {}).get("line", ""),
                    "requires login",  # Semgrep does not output raw secret
                    "Semgrep",
                    item.get("extra", {}).get("severity", ""),
                    item.get("extra", {}).get("message", ""),
                    item.get("extra", {}).get("metadata", {}).get("source-rule-url", ""),
                ])
    except Exception as e:
        print(f"[!] Error parsing Semgrep report: {e}")
    return results

def process_trufflehog(trufflehog_path):
    results = []
    try:
        with open(trufflehog_path, 'r') as f:
            for line in f:
                try:
                    item = json.loads(line)
                    if "Raw" not in item:
                        continue
                    file_path = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "")
                    line_no = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", "")
                    secret = item.get("Raw", "")
                    key = normalize_key("trufflehog", file_path, line_no, secret)
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append([
                        item.get("DetectorName", ""),
                        file_path,
                        line_no,
                        secret,
                        "TruffleHog",
                        "Unknown",
                        item.get("DetectorDescription", ""),
                        item.get("ExtraData", {}).get("rotation_guide", ""),
                    ])
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        print(f"[!] Error parsing TruffleHog report: {e}")
    return results

# Process both tools
semgrep_results = process_semgrep(semgrep_file)
trufflehog_results = process_trufflehog(trufflehog_file)

# Write to CSV
with open(output_csv, mode='w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(headers)
    for row in semgrep_results + trufflehog_results:
        writer.writerow(row)

print(f"[✓] Combined secrets written to: {output_csv}")
