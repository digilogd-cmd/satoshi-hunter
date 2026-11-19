"""
Satoshi Hunter - Multi-Chain Pattern Matcher & Crypto Key Validator
Pure Python standard library implementation for:
- BIP-39 Mnemonics (12/15/18/21/24 words - BTC, ETH, SOL, DOGE, etc.)
- Bitcoin (Legacy P2PKH, P2SH, Native SegWit bc1q, Taproot bc1p, WIF Private Keys)
- HD Wallet Extended Master Private Keys (xprv, yprv, zprv, Ltpv)
- Ethereum & EVM Chains (0x Addresses, Keystore JSON vaults, 64-Hex Private Keys)
- Dogecoin (D... Addresses & Q/6... WIF Keys)
- Litecoin (L/M/ltc1... Addresses & T/6... WIF Keys)
- Tron / USDT-TRC20 (T... Addresses)
- Solana (Phantom/Solana CLI 64-byte secret key arrays)
"""

import re
import json
import hashlib
from typing import List, Dict, Any, Optional
from satoshi_hunter.detector.bip39_words import BIP39_WORDLIST

# Base58 Alphabet
B58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
B58_MAP = {c: i for i, c in enumerate(B58_CHARS)}

def b58decode(s: str) -> Optional[bytes]:
    """Decodes a base58 string into bytes."""
    num = 0
    for char in s:
        if char not in B58_MAP:
            return None
        num = num * 58 + B58_MAP[char]
    
    combined = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big') if num > 0 else b''
    pad_len = 0
    for c in s:
        if c == '1':
            pad_len += 1
        else:
            break
    return (b'\x00' * pad_len) + combined

def decode_b58check(s: str) -> Optional[bytes]:
    """Validates Base58Check checksum and returns payload bytes (including version byte) if valid."""
    raw = b58decode(s)
    if not raw or len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    h = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    if h[:4] == checksum:
        return payload
    return None

def validate_b58_checksum(s: str) -> bool:
    """Validates Base58Check encoding."""
    return decode_b58check(s) is not None

# Bech32 validation (Bitcoin bc1... & Litecoin ltc1...)
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def verify_bech32_checksum(hrp: str, data: List[int]) -> bool:
    chk = bech32_polymod(bech32_hrp_expand(hrp) + data)
    return chk in (1, 0x2bc830a3)

def validate_bech32_prefix(addr: str, hrp_expected: str = "bc") -> bool:
    """Validates Bech32/Bech32m address for given human-readable prefix (e.g. 'bc' or 'ltc')."""
    if addr.lower() != addr and addr.upper() != addr:
        return False
    addr = addr.lower()
    sep_prefix = hrp_expected + "1"
    if not addr.startswith(sep_prefix):
        return False
    data_part = addr[len(sep_prefix):]
    if len(data_part) < 6:
        return False
    data = []
    for c in data_part:
        idx = BECH32_CHARSET.find(c)
        if idx == -1:
            return False
        data.append(idx)
    return verify_bech32_checksum(hrp_expected, data)

def validate_bech32(addr: str) -> bool:
    return validate_bech32_prefix(addr, "bc")

# =========================================================
# REGEX PATTERNS FOR MULTI-CHAIN ASSETS
# =========================================================

# 1. Base58 Address Candidates (BTC 1/3, DOGE D, LTC L/M, TRON T)
RE_BASE58_ADDR = re.compile(r'\b[13DLMT][1-9A-HJ-NP-Za-km-z]{25,34}\b')

# 2. Bech32 Native SegWit / Taproot (Bitcoin bc1... & Litecoin ltc1...)
RE_BTC_BECH32 = re.compile(r'\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,62}\b', re.IGNORECASE)
RE_LTC_BECH32 = re.compile(r'\bltc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,62}\b', re.IGNORECASE)

# 3. WIF Private Keys (BTC: 5/K/L, DOGE: 6/Q, LTC: 6/T)
RE_WIF_KEY = re.compile(r'\b[56KLQT][1-9A-HJ-NP-Za-km-z]{50,51}\b')

# 4. BIP-32/44/49/84 Extended Master Private Keys (xprv, yprv, zprv, Ltpv)
RE_XPRV_KEY = re.compile(r'\b(?:xprv|yprv|zprv|Ltpv)[1-9A-HJ-NP-Za-km-z]{104,108}\b')

# 5. Ethereum & EVM Address (0x + 40 hex chars)
RE_ETH_ADDR = re.compile(r'\b0x[0-9a-fA-F]{40}\b')

# 6. 64-Hex Private Key (BTC/ETH/EVM/DOGE/SOL raw hex near crypto keywords)
RE_HEX_KEY = re.compile(r'\b(?:0x)?[0-9a-fA-F]{64}\b')
RE_CRYPTO_CONTEXT = re.compile(
    r'(?:priv|private|key|secret|seed|wallet|btc|bitcoin|eth|ethereum|doge|sol|solana|mnemonic|keystore|지갑|개인키|비밀키|시드|니모닉)',
    re.IGNORECASE
)

# 7. Solana CLI / Phantom 64-byte Secret Key JSON Array (e.g. [12, 234, 55, ... 64 integers])
RE_SOLANA_KEY_ARRAY = re.compile(r'\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]')


def find_mnemonics_in_text(text: str) -> List[Dict[str, Any]]:
    """
    Finds valid BIP-39 mnemonic phrases (12, 15, 18, 21, 24 words).
    Compatible across Bitcoin, Ethereum, MetaMask, Solana, Dogecoin, Ledger, Trezor, etc.
    """
    results = []
    seen_phrases = set()
    lines = text.splitlines()
    for line_idx, line in enumerate(lines, 1):
        words = re.findall(r'[a-zA-Z]+', line.lower())
        if len(words) < 12:
            continue
        
        for length in (24, 21, 18, 15, 12):
            if len(words) < length:
                continue
            for i in range(len(words) - length + 1):
                window = words[i:i + length]
                if all(w in BIP39_WORDLIST for w in window):
                    phrase = " ".join(window)
                    if any(phrase in s for s in seen_phrases):
                        continue
                    seen_phrases.add(phrase)
                    results.append({
                        "type": f"BIP-39 멀티체인 시드 구문 ({length} Words - BTC/ETH/SOL 공용)",
                        "value": phrase,
                        "line": line_idx,
                        "confidence": "CRITICAL",
                        "chain": "MULTI"
                    })
    return results


def find_crypto_keys_and_addresses(text: str) -> List[Dict[str, Any]]:
    """Scans text for mathematically valid private keys, master keys, vaults, and addresses across major chains."""
    findings = []
    seen = set()

    def add_finding(f_type: str, val: str, conf: str, chain: str):
        key = (f_type, val)
        if key not in seen:
            seen.add(key)
            findings.append({
                "type": f_type,
                "value": val,
                "confidence": conf,
                "chain": chain
            })

    # 1. Extended Master Private Keys (xprv / yprv / zprv / Ltpv)
    for match in RE_XPRV_KEY.finditer(text):
        candidate = match.group(0)
        if decode_b58check(candidate) is not None:
            add_finding("HD 지갑 마스터 개인키 (Extended Private Key - xprv/zprv)", candidate, "CRITICAL", "BTC")

    # 2. WIF Private Keys (Bitcoin, Dogecoin, Litecoin)
    for match in RE_WIF_KEY.finditer(text):
        candidate = match.group(0)
        payload = decode_b58check(candidate)
        if payload and len(payload) in (33, 34):
            ver = payload[0]
            if ver == 0x80:
                add_finding("Bitcoin WIF 개인키 (Private Key)", candidate, "CRITICAL", "BTC")
            elif ver == 0x9E:
                add_finding("Dogecoin WIF 개인키 (Private Key)", candidate, "CRITICAL", "DOGE")
            elif ver == 0xB0:
                add_finding("Litecoin WIF 개인키 (Private Key)", candidate, "CRITICAL", "LTC")

    # 3. Base58Check Addresses (Bitcoin 1/3, Dogecoin D, Litecoin L/M, Tron T)
    for match in RE_BASE58_ADDR.finditer(text):
        candidate = match.group(0)
        payload = decode_b58check(candidate)
        if payload and len(payload) == 21:
            ver = payload[0]
            if ver == 0x00 and candidate.startswith('1'):
                add_finding("Bitcoin 주소 (Legacy P2PKH)", candidate, "HIGH", "BTC")
            elif ver == 0x05 and candidate.startswith('3'):
                add_finding("Bitcoin 주소 (P2SH SegWit/MultiSig)", candidate, "HIGH", "BTC")
            elif ver == 0x1E and candidate.startswith('D'):
                add_finding("Dogecoin 주소 (DOGE)", candidate, "HIGH", "DOGE")
            elif ver in (0x30, 0x32) and candidate[0] in ('L', 'M'):
                add_finding("Litecoin 주소 (LTC)", candidate, "HIGH", "LTC")
            elif ver == 0x41 and candidate.startswith('T'):
                add_finding("Tron / USDT(TRC-20) 주소 (TRX)", candidate, "HIGH", "TRX")

    # 4. Bitcoin Native SegWit & Taproot ('bc1...')
    for match in RE_BTC_BECH32.finditer(text):
        candidate = match.group(0)
        if validate_bech32_prefix(candidate, "bc"):
            addr_type = "Taproot" if candidate.lower().startswith("bc1p") else "Native SegWit"
            add_finding(f"Bitcoin 주소 ({addr_type})", candidate, "HIGH", "BTC")

    # 5. Litecoin Native SegWit ('ltc1...')
    for match in RE_LTC_BECH32.finditer(text):
        candidate = match.group(0)
        if validate_bech32_prefix(candidate, "ltc"):
            add_finding("Litecoin 주소 (Native SegWit ltc1)", candidate, "HIGH", "LTC")

    # 6. Ethereum / EVM Keystore JSON Content Inspection (even if filename is generic)
    if '"crypto"' in text.lower() and '"ciphertext"' in text.lower() and '"kdf"' in text.lower():
        add_finding("Ethereum / EVM 암호화 키스토어 볼트 (Web3 Keystore JSON)", "Encrypted Web3 Keystore JSON Container", "CRITICAL", "ETH")

    # 7. Solana 64-byte Secret Key JSON Array
    for match in RE_SOLANA_KEY_ARRAY.finditer(text):
        arr_str = match.group(0)
        try:
            nums = json.loads(arr_str)
            if isinstance(nums, list) and len(nums) == 64 and all(isinstance(x, int) and 0 <= x <= 255 for x in nums):
                add_finding("Solana 개인키 배열 (Phantom / Solana Keypair 64-Byte)", arr_str, "CRITICAL", "SOL")
        except Exception:
            pass

    # 8. Ethereum / EVM Addresses (0x + 40 hex chars)
    # Require either EIP-55 mixed case OR nearby crypto context to avoid matching random git commit hashes
    for match in RE_ETH_ADDR.finditer(text):
        candidate = match.group(0)
        hex_body = candidate[2:]
        is_mixed_case = (hex_body.lower() != hex_body and hex_body.upper() != hex_body)
        start = max(0, match.start() - 80)
        end = min(len(text), match.end() + 80)
        has_context = bool(RE_CRYPTO_CONTEXT.search(text[start:end]))
        if is_mixed_case or has_context:
            add_finding("Ethereum / EVM 지갑 주소 (ETH/BNB/MATIC/ERC-20)", candidate, "HIGH", "ETH")

    # 9. Raw 64-Hex Private Keys near context keywords
    for match in RE_HEX_KEY.finditer(text):
        start = max(0, match.start() - 70)
        end = min(len(text), match.end() + 70)
        surrounding = text[start:end]
        if RE_CRYPTO_CONTEXT.search(surrounding):
            val = match.group(0)
            if not val.lower().startswith("00000000") and not val.lower().startswith("ffffffff"):
                add_finding("64-Hex 원본 개인키 (BTC / ETH / EVM 호환)", val, "CRITICAL", "MULTI")

    return findings


def get_explorer_url(value: str, val_type: str, chain: str = "") -> Optional[str]:
    """Returns the appropriate blockchain explorer URL for an address."""
    if "주소" not in val_type and "Address" not in val_type:
        return None
    if chain == "ETH" or value.startswith("0x"):
        return f"https://etherscan.io/address/{value}"
    if chain == "DOGE" or value.startswith("D"):
        return f"https://blockchair.com/dogecoin/address/{value}"
    if chain == "LTC" or value.lower().startswith("ltc1") or value[0] in ("L", "M"):
        return f"https://litecoinspace.org/address/{value}"
    if chain == "TRX" or value.startswith("T"):
        return f"https://tronscan.org/#/address/{value}"
    return f"https://mempool.space/address/{value}"


def mask_secret(value: str, val_type: str) -> str:
    """Masks secret values for safe reporting while keeping identifiable prefix/suffix."""
    if any(k in val_type for k in ("Private Key", "개인키", "Keypair")):
        if len(value) <= 14:
            return value[:3] + "..." + value[-3:]
        return value[:7] + " ... [SECRET HIDDEN] ... " + value[-6:]
    elif any(k in val_type for k in ("Mnemonic", "시드")):
        words = value.split()
        if len(words) >= 12:
            return f"{words[0]} {words[1]} ... ({len(words)-4} words hidden) ... {words[-2]} {words[-1]}"
        return value
    return value
