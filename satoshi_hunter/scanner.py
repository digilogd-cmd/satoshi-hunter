"""
Satoshi Hunter - File System Scanner Engine
Rapidly scans directories for cryptocurrency wallet files, seed phrases, private keys, and addresses.
"""

import os
import sys
import glob
from typing import List, Dict, Any, Callable, Optional, Set
from satoshi_hunter.detector.wallet_files import (
    get_known_appdata_targets,
    check_file_for_wallet_signature
)
from satoshi_hunter.detector.patterns import (
    find_crypto_keys_and_addresses,
    find_mnemonics_in_text
)

# Text extensions to inspect content
TEXT_EXTENSIONS = {
    ".txt", ".csv", ".json", ".md", ".log", ".cfg", ".ini", 
    ".yaml", ".yml", ".memo", ".xml", ".html", ".py", ".sh", ".bat"
}

# Ignore common bloated or system directories
IGNORE_DIRS = {
    "$recycle.bin", "system volume information", "windows", "winsxs",
    "node_modules", ".git", ".svn", ".venv", "venv", "site-packages",
    "cache", "caches", "temp", "tmp", "microsoft", "package cache",
    "assembly", "servicing", "system32", "syswow64"
}

# Max file size to inspect text content (5MB)
MAX_TEXT_SIZE_BYTES = 5 * 1024 * 1024

class HunterScanner:
    def __init__(self, progress_callback: Optional[Callable[[int, int, str], None]] = None):
        self.progress_callback = progress_callback
        self.wallet_findings: List[Dict[str, Any]] = []
        self.text_findings: List[Dict[str, Any]] = []
        self.files_scanned = 0
        self.total_matches = 0

    def is_ignored_dir(self, dir_name: str) -> bool:
        return dir_name.lower() in IGNORE_DIRS or dir_name.startswith("$")

    def scan_file_content(self, filepath: str) -> List[Dict[str, Any]]:
        """Reads and searches a file for mnemonics, private keys, and addresses."""
        findings = []
        try:
            size = os.path.getsize(filepath)
            if size > MAX_TEXT_SIZE_BYTES or size == 0:
                return []

            # Try reading with common encodings
            content = None
            for enc in ("utf-8", "cp949", "euc-kr", "latin-1"):
                try:
                    with open(filepath, "r", encoding=enc, errors="ignore") as f:
                        content = f.read()
                        break
                except Exception:
                    continue

            if not content:
                return []

            # Check mnemonics
            mnemonics = find_mnemonics_in_text(content)
            for m in mnemonics:
                m["filepath"] = filepath
                findings.append(m)

            # Check keys & addresses
            keys = find_crypto_keys_and_addresses(content)
            for k in keys:
                k["filepath"] = filepath
                findings.append(k)

        except Exception:
            pass

        return findings

    def scan_path(self, root_path: str, quick_mode: bool = False):
        """Recursively scans a root directory path."""
        if not os.path.exists(root_path):
            return

        for root, dirs, files in os.walk(root_path):
            # Filter ignored directories in-place
            dirs[:] = [d for d in dirs if not self.is_ignored_dir(d)]

            for file in files:
                self.files_scanned += 1
                filepath = os.path.join(root, file)

                if self.progress_callback:
                    self.progress_callback(self.files_scanned, self.total_matches, filepath)

                # 1. Check known wallet signatures
                wallet_sig = check_file_for_wallet_signature(filepath)
                if wallet_sig:
                    self.wallet_findings.append(wallet_sig)
                    self.total_matches += 1
                    continue

                # 2. Check text contents for potential keys/mnemonics
                _, ext = os.path.splitext(file.lower())
                name_lower = file.lower()

                # High interest filenames get scanned even if extension is unusual
                is_high_interest = any(kw in name_lower for kw in [
                    "wallet", "bitcoin", "btc", "seed", "mnemonic", "crypto", "개인키", "지갑", "비밀키"
                ])

                if ext in TEXT_EXTENSIONS or is_high_interest:
                    res = self.scan_file_content(filepath)
                    if res:
                        self.text_findings.extend(res)
                        self.total_matches += len(res)

    def run_quick_scan(self):
        """
        Executes a rapid targeted scan on User Profile hot spots:
        - Desktop, Downloads, Documents
        - Known AppData wallet directories
        """
        userprofile = os.environ.get("USERPROFILE", "")
        hotspots = []

        if userprofile:
            hotspots.extend([
                os.path.join(userprofile, "Desktop"),
                os.path.join(userprofile, "Downloads"),
                os.path.join(userprofile, "Documents"),
                os.path.join(userprofile, "OneDrive", "Desktop"),
                os.path.join(userprofile, "OneDrive", "Documents"),
            ])

        # Add known AppData targets
        appdata_targets = get_known_appdata_targets()
        for t in appdata_targets:
            p = t["path"]
            if os.path.exists(p):
                hotspots.append(p)

        # Remove duplicates
        unique_hotspots = []
        for p in hotspots:
            p_norm = os.path.abspath(p)
            if os.path.exists(p_norm) and p_norm not in unique_hotspots:
                unique_hotspots.append(p_norm)

        for path in unique_hotspots:
            self.scan_path(path, quick_mode=True)
