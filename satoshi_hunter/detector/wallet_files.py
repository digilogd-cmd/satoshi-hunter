"""
Satoshi Hunter - Multi-Chain Wallet Files & Browser Extension Vault Detector
Detects:
- Desktop Wallets: Bitcoin Core, Dogecoin Core, Litecoin Core, Electrum, Sparrow,
  Exodus, Atomic, Coinomi, Monero GUI, Armory, MultiBit, Ledger Live, Trezor Suite.
- Browser Extension Vaults (Chrome, Brave, Edge, Naver Whale):
  MetaMask, Phantom (Solana), Rabby, Coinbase Wallet, Trust Wallet, OKX Wallet,
  Keplr (Cosmos), TronLink (TRX/USDT), Kaikas (Kaia/Klaytn), Binance Wallet.
- Web3 Keystore JSONs (UTC--* and internal encrypted keystore structure).
"""

import os
from typing import List, Dict, Any, Optional

KNOWN_WALLET_FILENAMES = {
    "wallet.dat": ("Bitcoin / Dogecoin / Litecoin Core 지갑 DB (wallet.dat)", "CRITICAL"),
    "wallet.dat.bak": ("Core 지갑 백업 DB (wallet.dat.bak)", "CRITICAL"),
    "default_wallet": ("Electrum 기본 지갑 파일 (default_wallet)", "CRITICAL"),
    "secrethash.dat": ("Exodus 시드 해시 볼트 (secrethash.dat)", "CRITICAL"),
    "seed.seco": ("Exodus 암호화 시드 금고 (seed.seco)", "CRITICAL"),
    "info.seco": ("Exodus 지갑 메타데이터 (info.seco)", "HIGH"),
    "multibit.wallet": ("MultiBit 클래식 지갑 (multibit.wallet)", "CRITICAL"),
    "multibit.key": ("MultiBit 개인키 백업 (multibit.key)", "CRITICAL"),
    "keypair.json": ("Solana CLI 키페어 지갑 (keypair.json)", "CRITICAL"),
    "id.json": ("Solana 기본 키페어 지갑 (id.json)", "HIGH"),
}

# Known Chrome/Brave/Edge/Whale Web3 Wallet Extension IDs
BROWSER_EXTENSION_WALLETS = {
    "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask (이더리움/EVM 지갑 볼트)",
    "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom (솔라나/멀티체인 지갑 볼트)",
    "acmacodkjbdgmoleebolmdjonilkdbch": "Rabby Wallet (EVM 디파이 지갑 볼트)",
    "hnfanknocfeofbddgcijnmhnfnkdnaad": "Coinbase Wallet (코인베이스 지갑 볼트)",
    "egjidjbpglichdcondbcbdnbeeppgdph": "Trust Wallet (트러스트 멀티체인 볼트)",
    "mcohilncbfahbmgdjkbpemcciiolgcge": "OKX Web3 Wallet (OKX 지갑 볼트)",
    "dmkamcknogkgcdfhhbddcghachkejeap": "Keplr (코스모스 생태계 지갑 볼트)",
    "ibnejdfjmmkpcnlpebklmnkoeoihofec": "TronLink (트론/USDT 지갑 볼트)",
    "jblndlipeogpafnldhgmapagcccfchpi": "Kaikas / Kaia (카이아/클레이튼 지갑 볼트)",
    "fhbohimaelbohpjbbldcngcnapndodjp": "Binance Chain Wallet (바이낸스 지갑 볼트)",
}

# Suspicious file extensions for wallet databases
WALLET_EXTENSIONS = {
    ".wallet": "암호화폐 지갑 컨테이너 (.wallet)",
    ".keys": "Monero (XMR) / 암호화폐 키 파일 (.keys)",
    ".key": "암호화폐 개인키 백업 파일 (.key)",
    ".priv": "개인키 데이터 파일 (.priv)",
    ".seed": "니모닉 시드 백업 파일 (.seed)",
    ".kdbx": "KeePass 암호화 보안 금고 (.kdbx)",
    ".mv.db": "Sparrow 비트코인 지갑 DB (.mv.db)",
}

def get_known_appdata_targets() -> List[Dict[str, str]]:
    appdata = os.environ.get("APPDATA", "")
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    userprofile = os.environ.get("USERPROFILE", "")

    targets = []
    
    if appdata:
        targets.extend([
            {"name": "Bitcoin Core Wallets", "path": os.path.join(appdata, "Bitcoin", "wallets")},
            {"name": "Bitcoin Core Root", "path": os.path.join(appdata, "Bitcoin")},
            {"name": "Dogecoin Core", "path": os.path.join(appdata, "Dogecoin")},
            {"name": "Litecoin Core", "path": os.path.join(appdata, "Litecoin")},
            {"name": "Electrum BTC Wallets", "path": os.path.join(appdata, "Electrum", "wallets")},
            {"name": "Electrum LTC Wallets", "path": os.path.join(appdata, "Electrum-LTC", "wallets")},
            {"name": "Sparrow Bitcoin Wallets", "path": os.path.join(appdata, "Sparrow", "wallets")},
            {"name": "Exodus Wallet Vault", "path": os.path.join(appdata, "Exodus", "exodus.wallet")},
            {"name": "Atomic Wallet Vault", "path": os.path.join(appdata, "atomic", "Local Storage", "leveldb")},
            {"name": "Armory Wallets", "path": os.path.join(appdata, "Armory")},
            {"name": "Ledger Live Config", "path": os.path.join(appdata, "Ledger Live")},
            {"name": "Trezor Suite Desktop", "path": os.path.join(appdata, "@trezor", "suite-desktop")},
        ])

    if local_appdata:
        targets.append({
            "name": "Coinomi Multi-Chain Wallets",
            "path": os.path.join(local_appdata, "Coinomi", "Coinomi", "wallets")
        })

    if userprofile:
        targets.extend([
            {"name": "Monero GUI Wallets", "path": os.path.join(userprofile, "Documents", "Monero", "wallets")},
            {"name": "Solana CLI Keys", "path": os.path.join(userprofile, ".config", "solana")},
        ])

    # Chrome / Brave / Edge / Whale Browser Extension Vaults
    browser_profiles = [
        ("Chrome", os.path.join(local_appdata, "Google", "Chrome", "User Data", "Default", "Local Extension Settings")),
        ("Brave", os.path.join(local_appdata, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Extension Settings")),
        ("Edge", os.path.join(local_appdata, "Microsoft", "Edge", "User Data", "Default", "Local Extension Settings")),
        ("Whale", os.path.join(local_appdata, "Naver", "Naver Whale", "User Data", "Default", "Local Extension Settings")),
    ]

    for b_name, ext_root in browser_profiles:
        if os.path.exists(ext_root):
            for ext_id, wallet_desc in BROWSER_EXTENSION_WALLETS.items():
                vault_dir = os.path.join(ext_root, ext_id)
                if os.path.exists(vault_dir):
                    targets.append({"name": f"{b_name} {wallet_desc}", "path": vault_dir})

    return targets


def check_file_for_wallet_signature(filepath: str) -> Optional[Dict[str, Any]]:
    """Checks if a file matches known multi-chain wallet filenames, browser vaults, or binary signatures."""
    basename = os.path.basename(filepath).lower()
    norm_path = filepath.replace("/", "\\").lower()

    # 0. Check if inside a known Browser Extension Wallet Vault directory (.ldb / .log containing encrypted vault)
    for ext_id, wallet_desc in BROWSER_EXTENSION_WALLETS.items():
        if ext_id in norm_path and basename.endswith((".ldb", ".log")):
            try:
                if os.path.getsize(filepath) > 32:
                    with open(filepath, "rb") as f:
                        raw = f.read(256 * 1024)
                    if b"vault" in raw or b"keyring" in raw or b"mnemonic" in raw or b"cipher" in raw:
                        return {
                            "type": f"웹 브라우저 확장 지갑 금고: {wallet_desc}",
                            "filepath": filepath,
                            "filename": basename,
                            "confidence": "CRITICAL",
                            "size": os.path.getsize(filepath)
                        }
            except Exception:
                pass

    # 1. Exact filename match
    if basename in KNOWN_WALLET_FILENAMES:
        desc, confidence = KNOWN_WALLET_FILENAMES[basename]
        # Disambiguate Bitcoin vs Dogecoin vs Litecoin wallet.dat by parent directory
        if basename.startswith("wallet.dat"):
            if "dogecoin" in norm_path:
                desc = "Dogecoin Core 지갑 DB (wallet.dat)"
            elif "litecoin" in norm_path:
                desc = "Litecoin Core 지갑 DB (wallet.dat)"
            elif "bitcoin" in norm_path:
                desc = "Bitcoin Core 지갑 DB (wallet.dat)"
        return {
            "type": desc,
            "filepath": filepath,
            "filename": basename,
            "confidence": confidence,
            "size": os.path.getsize(filepath) if os.path.exists(filepath) else 0
        }

    # 2. Ledger Live app.json (contains accounts & xpub/derivation paths)
    if basename == "app.json" and "ledger live" in norm_path:
        return {
            "type": "Ledger Live 하드웨어 지갑 계정 DB (app.json)",
            "filepath": filepath,
            "filename": basename,
            "confidence": "HIGH",
            "size": os.path.getsize(filepath) if os.path.exists(filepath) else 0
        }

    # 3. Ethereum / EVM Keystore filename pattern (UTC--20xx-...)
    if basename.startswith("utc--") and (basename.endswith(".json") or "--" in basename):
        return {
            "type": "Ethereum / EVM 표준 키스토어 파일 (UTC--Keystore)",
            "filepath": filepath,
            "filename": basename,
            "confidence": "CRITICAL",
            "size": os.path.getsize(filepath) if os.path.exists(filepath) else 0
        }

    # 4. Extension matches (.wallet, .keys, .key, .priv, .seed, .kdbx, .mv.db)
    for ext, ext_desc in WALLET_EXTENSIONS.items():
        if basename.endswith(ext):
            return {
                "type": ext_desc,
                "filepath": filepath,
                "filename": basename,
                "confidence": "HIGH" if ext != ".keys" else "CRITICAL",
                "size": os.path.getsize(filepath) if os.path.exists(filepath) else 0
            }

    # 5. Binary signature inspection for Berkeley DB (renamed wallet.dat for BTC/LTC/DOGE)
    try:
        if os.path.isfile(filepath) and 1024 < os.path.getsize(filepath) < 50 * 1024 * 1024:
            with open(filepath, "rb") as f:
                header = f.read(64)
                if b"\x00\x05\x31\x62" in header or b"\x62\x31\x05\x00" in header:
                    f.seek(0)
                    chunk = f.read(16384)
                    if any(sig in chunk for sig in (b"mkey", b"ckey", b"defaultkey", b"pool")):
                        return {
                            "type": "이름이 변경된 Core 지갑 DB (Berkeley DB Magic Bytes 일치 - BTC/DOGE/LTC)",
                            "filepath": filepath,
                            "filename": basename,
                            "confidence": "CRITICAL",
                            "size": os.path.getsize(filepath)
                        }
    except Exception:
        pass

    return None
