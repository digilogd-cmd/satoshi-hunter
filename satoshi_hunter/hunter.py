"""
====================================================================
 🛰️  SATOSHI HUNTER (사토시 헌터) v1.0
 내 컴퓨터 안에 숨어 있는 잠자는 비트코인 자산 탐지기
====================================================================
찾은 건 내 PC 밖으로 안 나가요 - 밖으로 보내는 코드 없음 (코드는 누구나 열어 볼 수 있음)
"""

import os
import sys
import time
import argparse
import webbrowser

# Ensure UTF-8 console output on Windows
if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from satoshi_hunter.scanner import HunterScanner
from satoshi_hunter.reporter import generate_html_report
from satoshi_hunter.detector.patterns import mask_secret

BANNER = r"""
  ==============================================================
    ____        _            _          _   _             _            
   / ___|  __ _| |_ ___  ___| |__  (_) | | | |_   _ _ __ | |_ ___ _ __ 
   \___ \ / _` | __/ _ \/ __| '_ \ | | | |_| | | | | '_ \| __/ _ \ '__|
    ___) | (_| | || (_) \__ \ | | || | |  _  | |_| | | | | ||  __/ |   
   |____/ \__,_|\__\___/|___/_| |_|/ | |_| |_|\__,_|_| |_|\__\___|_|   
                                  |__/                                 
  ==============================================================
   🪙  내 컴퓨터 속 잠자는 비트코인 & 시드 구문 탐색 레이더 🛰️
  ==============================================================
"""

def print_banner():
    print("\033[93m" + BANNER + "\033[0m")
    print("\033[92m[*] 보안 확인: 찾은 건 내 PC 밖으로 안 나가요. 와이파이를 끄고 돌려도 됩니다.\033[0m")
    print("\033[90m[*] 찾은 영단어·개인키는 어디에도 붙여 넣거나 보내지 마세요. \"복구해 드려요\" 연락은 의심부터.\033[0m\n")

def run_scanner(target_path: str = None, quick: bool = True):
    print("=" * 65)
    if quick:
        print("🚀 [퀵 스캔 모드] 바탕화면, 다운로드, 문서, AppData 지갑 경로 스캔 시작...")
    else:
        print(f"🔍 [정밀 탐색 모드] 대상 경로: {target_path}")
    print("=" * 65)

    last_time = [time.time()]

    def progress_callback(scanned, matches, current_path):
        now = time.time()
        # Update progress at most every 0.1s to avoid console flickering
        if now - last_time[0] > 0.1:
            last_time[0] = now
            cur_display = current_path
            if len(cur_display) > 50:
                cur_display = "..." + cur_display[-47:]
            sys.stdout.write(f"\r\033[K[스캔 중] 검사: {scanned:,}개 | 🎯 탐지: \033[91m{matches}\033[0m개 | {cur_display}")
            sys.stdout.flush()

    scanner = HunterScanner(progress_callback=progress_callback)
    start_t = time.time()

    if quick:
        scanner.run_quick_scan()
    else:
        scanner.scan_path(target_path)

    sys.stdout.write("\r\033[K")
    sys.stdout.flush()

    elapsed = time.time() - start_t
    print("\n" + "=" * 65)
    print("🎉 탐색 완료!")
    print(f"⏱️ 소요 시간: {elapsed:.2f}초")
    print(f"📂 총 검사 파일 수: {scanner.files_scanned:,}개")
    print(f"🎯 총 탐지 자산 수: {scanner.total_matches}개")
    print("=" * 65)

    # Print summary
    if scanner.wallet_findings:
        print("\n\033[93m[💼 발견된 암호화폐 지갑 파일]\033[0m")
        for w in scanner.wallet_findings:
            print(f"  • \033[91m{w['type']}\033[0m: {w['filepath']}")

    if scanner.text_findings:
        print("\n\033[93m[🔑 발견된 시드 구문 / 개인키 / 비트코인 주소]\033[0m")
        for item in scanner.text_findings:
            masked = mask_secret(item['value'], item['type'])
            print(f"  • \033[96m{item['type']}\033[0m: {masked}")
            print(f"    └ 위치: {item['filepath']}")

    if scanner.total_matches == 0:
        print("\n💡 탐지된 지갑이나 시드 구문이 없습니다. (깨끗한 환경입니다!)")

    # Generate HTML report
    report_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "satoshi_hunter_report.html"))
    generate_html_report(
        files_scanned=scanner.files_scanned,
        wallet_findings=scanner.wallet_findings,
        text_findings=scanner.text_findings,
        output_path=report_file
    )

    print(f"\n📊 시각화 리포트가 생성되었습니다: \033[92m{report_file}\033[0m")
    try:
        webbrowser.open(f"file://{report_file}")
        print("🌐 브라우저에서 리포트를 자동으로 열었습니다!")
    except Exception:
        pass

    return scanner

def run_self_test():
    """Generates dummy files to verify multi-chain detector capabilities."""
    test_dir = os.path.join(os.path.dirname(__file__), "test_vault")
    os.makedirs(test_dir, exist_ok=True)
    
    sample_txt = os.path.join(test_dir, "old_backup_notes.txt")
    with open(sample_txt, "w", encoding="utf-8") as f:
        f.write("""
My Old Multi-Chain Crypto Notes (2017 Vault)
--------------------------------------------
Bitcoin Legacy Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
Bitcoin Native SegWit: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq
Bitcoin WIF Private Key: 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
HD Master Key (BIP32): xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi
Ethereum / EVM Wallet: 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
Dogecoin Wallet: DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L
Litecoin Wallet: LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL
Tron / USDT-TRC20 Wallet: TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL
Mnemonic Seed Backup (BTC/ETH/SOL/MetaMask):
army van defense carry jealous true garbage claim echo media make crunch
        """)
        
    print(f"\n🧪 [멀티체인 테스트 샘플 생성 완료] -> {test_dir}")
    print("가상 샘플에 대한 탐지 테스트를 즉시 시작합니다...\n")
    run_scanner(test_dir, quick=False)

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Satoshi Hunter - Local Bitcoin & Key Detector")
    parser.add_argument("--path", type=str, help="Specific directory to scan")
    parser.add_argument("--test", action="store_true", help="Run self-diagnostic test")
    args = parser.parse_args()

    if args.test:
        run_self_test()
        return

    if args.path:
        run_scanner(target_path=args.path, quick=False)
        return

    print("원하시는 탐색 모드를 선택해주세요:")
    print("  [1] 🚀 빠른 탐색 (바탕화면, 다운로드, 문서, AppData 지갑 경로)")
    print("  [2] 🔍 특정 폴더/드라이브 직접 지정 탐색 (예: E:\\, D:\\)")
    print("  [3] 🧪 자가 테스트 (더미 암호화폐 데이터로 탐지기 성능 검증)")
    print()

    try:
        choice = input("선택 번호 (1/2/3) [기본값: 1]: ").strip()
    except EOFError:
        choice = "1"

    if choice == "2":
        path = input("탐색할 경로를 입력하세요: ").strip()
        if not path or not os.path.exists(path):
            print("⚠️ 유효하지 않은 경로입니다. 종료합니다.")
            return
        run_scanner(target_path=path, quick=False)
    elif choice == "3":
        run_self_test()
    else:
        run_scanner(quick=True)

if __name__ == "__main__":
    main()
