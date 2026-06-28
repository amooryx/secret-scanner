#!/usr/bin/env python3
"""
API Key & Secret Scanner - by amooryx
Scans URLs, JS files, and local files for leaked secrets using regex + Shannon entropy.
"""

import re
import sys
import math
import json
import argparse
import os
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] Missing dep: pip install requests")
    sys.exit(1)

BANNER = r"""
    ___    ____  ____   __ __ __             _____                                 
   /   |  / __ \/  _/  / //_// /__  __  __ / ___/_________ _____  ____  ___  _____
  / /| | / /_/ // /   / ,<  / / _ \/ / / / \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 / ___ |/ ____// /   / /| |/ /  __/ /_/ / ___/ / /__/ /_/ / / / / / / /  __/ /    
/_/  |_/_/   /___/  /_/ |_/_/\___/\__, / /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                                  /____/                                             

  API Key & Secret Scanner v1.0 | by amooryx
"""

# ─────────────────────────────────────────────
#  Secret Patterns
# ─────────────────────────────────────────────

PATTERNS = [
    # Generic high-entropy tokens
    {"name": "Generic API Key",        "regex": r'(?i)(api[_\-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'},
    {"name": "Generic Secret",         "regex": r'(?i)(secret[_\-]?key|client[_\-]?secret)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'},
    {"name": "Generic Token",          "regex": r'(?i)(access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})["\']?'},
    {"name": "Generic Password",       "regex": r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']'},

    # AWS
    {"name": "AWS Access Key ID",      "regex": r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])'},
    {"name": "AWS Secret Key",         "regex": r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'},

    # GitHub
    {"name": "GitHub Token",           "regex": r'(gh[pousr]_[A-Za-z0-9_]{36,255})'},
    {"name": "GitHub OAuth",           "regex": r'(gho_[A-Za-z0-9]{36,})'},

    # Google
    {"name": "Google API Key",         "regex": r'(AIza[0-9A-Za-z\-_]{35})'},
    {"name": "Google OAuth",           "regex": r'(ya29\.[0-9A-Za-z\-_]+)'},

    # Stripe
    {"name": "Stripe Secret Key",      "regex": r'(sk_live_[0-9a-zA-Z]{24,})'},
    {"name": "Stripe Publishable Key", "regex": r'(pk_live_[0-9a-zA-Z]{24,})'},
    {"name": "Stripe Test Key",        "regex": r'(sk_test_[0-9a-zA-Z]{24,})'},

    # Slack
    {"name": "Slack Bot Token",        "regex": r'(xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24})'},
    {"name": "Slack User Token",       "regex": r'(xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{32})'},
    {"name": "Slack Webhook",          "regex": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'},

    # Twilio
    {"name": "Twilio Account SID",     "regex": r'(AC[a-z0-9]{32})'},
    {"name": "Twilio Auth Token",      "regex": r'(?i)twilio[_\-]?auth[_\-]?token\s*[=:]\s*["\']?([a-z0-9]{32})["\']?'},

    # SendGrid
    {"name": "SendGrid API Key",       "regex": r'(SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43})'},

    # Firebase
    {"name": "Firebase URL",           "regex": r'https://[a-z0-9-]+\.firebaseio\.com'},
    {"name": "Firebase API Key",       "regex": r'(?i)firebase[_\-]?api[_\-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{35,})["\']?'},

    # Private Keys
    {"name": "RSA Private Key",        "regex": r'-----BEGIN RSA PRIVATE KEY-----'},
    {"name": "Private Key (generic)",  "regex": r'-----BEGIN (EC|PGP|OPENSSH) PRIVATE KEY-----'},

    # JWT
    {"name": "JSON Web Token",         "regex": r'eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'},

    # Database URLs
    {"name": "PostgreSQL DSN",         "regex": r'postgres(?:ql)?://[^:]+:[^@]+@[^\s"\']+'},
    {"name": "MySQL DSN",              "regex": r'mysql://[^:]+:[^@]+@[^\s"\']+'},
    {"name": "MongoDB DSN",            "regex": r'mongodb(\+srv)?://[^:]+:[^@]+@[^\s"\']+'},
    {"name": "Redis DSN",              "regex": r'redis://:[^@]+@[^\s"\']+'},

    # HuggingFace
    {"name": "HuggingFace Token",      "regex": r'(hf_[A-Za-z]{34,})'},

    # Anthropic / OpenAI
    {"name": "OpenAI API Key",         "regex": r'(sk-[a-zA-Z0-9]{48,})'},
    {"name": "Anthropic API Key",      "regex": r'(sk-ant-[a-zA-Z0-9_\-]{93,})'},
]


# ─────────────────────────────────────────────
#  Shannon Entropy
# ─────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    if not data:
        return 0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def high_entropy_strings(content: str, min_length: int = 20, threshold: float = 4.0) -> List[Tuple[str, float]]:
    """Find high-entropy substrings that look like secrets."""
    # Look for base64-ish or hex-ish strings
    candidates = re.findall(r'["\']([A-Za-z0-9+/=_\-]{%d,})["\']' % min_length, content)
    results = []
    for candidate in candidates:
        entropy = shannon_entropy(candidate)
        if entropy >= threshold:
            results.append((candidate, entropy))
    return results


# ─────────────────────────────────────────────
#  Finding Model
# ─────────────────────────────────────────────

@dataclass
class Finding:
    source: str
    pattern_name: str
    value: str
    line_number: Optional[int] = None
    entropy: Optional[float] = None
    via_entropy: bool = False

    def redacted(self) -> str:
        if len(self.value) <= 8:
            return "***"
        return self.value[:4] + "***" + self.value[-4:]


# ─────────────────────────────────────────────
#  Scanner
# ─────────────────────────────────────────────

class SecretScanner:
    def __init__(self, entropy_threshold: float = 4.0, min_length: int = 20, show_full: bool = False):
        self.entropy_threshold = entropy_threshold
        self.min_length = min_length
        self.show_full = show_full
        self.findings: List[Finding] = []

    def _scan_content(self, content: str, source: str):
        lines = content.splitlines()

        # Pattern-based
        for pat in PATTERNS:
            for m in re.finditer(pat["regex"], content):
                # Extract actual secret value (last group if grouped, else full match)
                value = m.group(len(m.groups())) if m.groups() else m.group(0)
                # Find line number
                line_num = content[:m.start()].count("\n") + 1
                entropy = shannon_entropy(value)
                self.findings.append(Finding(
                    source=source,
                    pattern_name=pat["name"],
                    value=value,
                    line_number=line_num,
                    entropy=round(entropy, 2),
                    via_entropy=False,
                ))

        # Entropy-based (catches unknowns)
        for val, entropy in high_entropy_strings(content, self.min_length, self.entropy_threshold):
            # Skip if already caught by pattern
            if any(f.value == val for f in self.findings):
                continue
            self.findings.append(Finding(
                source=source,
                pattern_name="High-Entropy String",
                value=val,
                entropy=round(entropy, 2),
                via_entropy=True,
            ))

    def scan_text(self, content: str, source: str = "<text>"):
        self._scan_content(content, source)

    def scan_file(self, path: str):
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
            print(f"  [*] Scanning file: {path}")
            self._scan_content(content, path)
        except FileNotFoundError:
            print(f"  [!] File not found: {path}")

    def scan_url(self, url: str, headers: Optional[Dict] = None):
        print(f"  [*] Fetching: {url}")
        try:
            r = requests.get(url, headers=headers or {}, timeout=15, verify=False)
            content = r.text
            self._scan_content(content, url)
        except Exception as e:
            print(f"  [!] Failed to fetch {url}: {e}")

    def scan_js_files(self, base_url: str, headers: Optional[Dict] = None):
        """Fetch a page and scan all linked JS files."""
        print(f"  [*] Crawling JS files from: {base_url}")
        try:
            r = requests.get(base_url, headers=headers or {}, timeout=15, verify=False)
            js_urls = re.findall(r'src=["\'](.*?\.js(?:\?[^"\']*)?)["\']', r.text)

            from urllib.parse import urljoin
            for js_path in js_urls:
                full_url = urljoin(base_url, js_path)
                self.scan_url(full_url, headers)
        except Exception as e:
            print(f"  [!] Failed crawling JS: {e}")

    def print_results(self):
        if not self.findings:
            print("\n  [-] No secrets found.")
            return

        print(f"\n  {'─'*70}")
        print(f"  FINDINGS ({len(self.findings)} total)")
        print(f"  {'─'*70}")

        by_source = {}
        for f in self.findings:
            by_source.setdefault(f.source, []).append(f)

        for source, findings in by_source.items():
            print(f"\n  Source: {source}")
            for f in findings:
                display = f.value if self.show_full else f.redacted()
                entropy_str = f"entropy={f.entropy}" if f.entropy else ""
                line_str = f"line {f.line_number}" if f.line_number else ""
                tag = "[ENTROPY]" if f.via_entropy else "[PATTERN]"
                print(f"    {tag} {f.pattern_name}")
                print(f"         Value  : {display}")
                if entropy_str or line_str:
                    print(f"         Info   : {', '.join(filter(None, [line_str, entropy_str]))}")

    def save_json(self, path: str):
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "total": len(self.findings),
            "findings": [
                {
                    "source": f.source,
                    "pattern": f.pattern_name,
                    "value": f.redacted(),
                    "line": f.line_number,
                    "entropy": f.entropy,
                    "via_entropy": f.via_entropy,
                }
                for f in self.findings
            ]
        }
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        print(f"\n  [+] JSON saved: {path}")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="API Key & Secret Scanner — regex + entropy analysis",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--url", help="URL to scan (fetches content)")
    parser.add_argument("-f", "--file", help="Local file to scan")
    parser.add_argument("-d", "--dir", help="Directory to scan recursively")
    parser.add_argument("--js", help="Crawl and scan JS files linked from URL")
    parser.add_argument("-l", "--list", help="File with URLs to scan (one per line)")
    parser.add_argument("-H", "--header", action="append", metavar="Key:Value",
                        help="Custom headers: -H 'Authorization: Bearer token'")
    parser.add_argument("--entropy", type=float, default=4.0,
                        help="Entropy threshold for unknown secrets (default: 4.0)")
    parser.add_argument("--min-length", type=int, default=20,
                        help="Minimum string length for entropy check (default: 20)")
    parser.add_argument("--show-full", action="store_true",
                        help="Show full secret values (default: redacted)")
    parser.add_argument("--json", help="Save results to JSON file")

    args = parser.parse_args()

    if not any([args.url, args.file, args.dir, args.js, args.list]):
        parser.print_help()
        sys.exit(1)

    # Parse headers
    headers = {}
    for h in args.header or []:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    scanner = SecretScanner(
        entropy_threshold=args.entropy,
        min_length=args.min_length,
        show_full=args.show_full,
    )

    if args.url:
        scanner.scan_url(args.url, headers)

    if args.js:
        scanner.scan_js_files(args.js, headers)

    if args.list:
        try:
            with open(args.list) as f:
                for url in f:
                    url = url.strip()
                    if url:
                        scanner.scan_url(url, headers)
        except FileNotFoundError:
            print(f"[!] List file not found: {args.list}")

    if args.file:
        scanner.scan_file(args.file)

    if args.dir:
        for root, _, files in os.walk(args.dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    scanner.scan_file(fpath)
                except Exception:
                    pass

    scanner.print_results()

    if args.json:
        scanner.save_json(args.json)

    print("\n[*] Done.")


if __name__ == "__main__":
    main()
