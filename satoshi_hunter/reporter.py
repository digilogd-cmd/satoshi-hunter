"""
Satoshi Hunter - Visual Reporter Engine
Generates interactive Dark-Mode Cyberpunk HTML report & Rich Console Summary.
"""

import os
import html
import datetime
from typing import List, Dict, Any
from satoshi_hunter.detector.patterns import mask_secret, get_explorer_url

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Satoshi Hunter - 잠자는 비트코인 탐지 리포트</title>
    <style>
        :root {
            --bg-base: #0b0f19;
            --bg-card: #131b2e;
            --border-glow: #f7931a;
            --accent-gold: #f7931a;
            --accent-cyan: #00f2fe;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --text-main: #f3f4f6;
            --text-sub: #9ca3af;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Pretendard", sans-serif;
            line-height: 1.6;
            padding: 30px 20px;
        }

        .container {
            max-width: 1100px;
            margin: 0 auto;
        }

        /* Header */
        .header {
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(180deg, rgba(247, 147, 26, 0.15) 0%, rgba(19, 27, 46, 0) 100%);
            border-radius: 20px;
            border: 1px solid rgba(247, 147, 26, 0.3);
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }

        .logo-icon {
            font-size: 54px;
            margin-bottom: 10px;
            filter: drop-shadow(0 0 15px rgba(247, 147, 26, 0.6));
        }

        h1 {
            font-size: 2.2rem;
            font-weight: 800;
            background: linear-gradient(90deg, #f7931a, #ffbe0b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }

        .subtitle {
            color: var(--text-sub);
            font-size: 1rem;
        }

        /* Privacy Banner */
        .privacy-badge {
            display: inline-block;
            margin-top: 15px;
            padding: 6px 16px;
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid var(--accent-green);
            color: #34d399;
            border-radius: 50px;
            font-size: 0.85rem;
            font-weight: 600;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 20px;
            margin-bottom: 35px;
        }

        .stat-card {
            background: var(--bg-card);
            padding: 24px;
            border-radius: 16px;
            border: 1px solid #1f2a44;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            transition: transform 0.2s, border-color 0.2s;
        }

        .stat-card:hover {
            transform: translateY(-4px);
            border-color: var(--border-glow);
        }

        .stat-val {
            font-size: 2.5rem;
            font-weight: 800;
            margin-top: 5px;
            color: var(--accent-gold);
        }

        .stat-label {
            font-size: 0.9rem;
            color: var(--text-sub);
        }

        /* Section */
        .section-title {
            font-size: 1.4rem;
            font-weight: 700;
            margin: 30px 0 15px 0;
            display: flex;
            align-items: center;
            gap: 10px;
            color: #ffffff;
        }

        /* Items Table / Cards */
        .item-card {
            background: var(--bg-card);
            border-radius: 12px;
            border: 1px solid #233150;
            padding: 20px;
            margin-bottom: 15px;
            transition: all 0.2s;
        }

        .item-card:hover {
            border-color: var(--accent-gold);
            box-shadow: 0 0 15px rgba(247, 147, 26, 0.2);
        }

        .item-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 10px;
        }

        .badge {
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }

        .badge-critical {
            background: rgba(239, 68, 68, 0.2);
            color: var(--accent-red);
            border: 1px solid var(--accent-red);
        }

        .badge-high {
            background: rgba(247, 147, 26, 0.2);
            color: var(--accent-gold);
            border: 1px solid var(--accent-gold);
        }

        .badge-medium {
            background: rgba(0, 242, 254, 0.2);
            color: var(--accent-cyan);
            border: 1px solid var(--accent-cyan);
        }

        .item-path {
            font-family: Consolas, monospace;
            font-size: 0.85rem;
            color: var(--text-sub);
            word-break: break-all;
            background: #090d16;
            padding: 8px 12px;
            border-radius: 8px;
            margin-top: 10px;
        }

        .item-value {
            font-family: Consolas, monospace;
            background: #060910;
            padding: 10px 14px;
            border-radius: 8px;
            color: #38bdf8;
            font-size: 0.95rem;
            word-break: break-all;
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-top: 10px;
            border: 1px dashed #233150;
        }

        .btn-toggle {
            background: #1e293b;
            color: #cbd5e1;
            border: none;
            padding: 4px 10px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.8rem;
            margin-left: 10px;
            white-space: nowrap;
        }

        .btn-toggle:hover {
            background: #334155;
            color: #fff;
        }

        .btn-explorer {
            display: inline-block;
            background: rgba(247, 147, 26, 0.2);
            color: var(--accent-gold);
            border: 1px solid var(--accent-gold);
            padding: 4px 12px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 0.8rem;
            font-weight: 600;
            margin-left: 10px;
            transition: all 0.2s;
        }

        .btn-explorer:hover {
            background: var(--accent-gold);
            color: #000;
        }

        .empty-state {
            text-align: center;
            padding: 40px;
            background: var(--bg-card);
            border-radius: 12px;
            border: 1px dashed #233150;
            color: var(--text-sub);
        }

        .footer {
            text-align: center;
            margin-top: 50px;
            color: var(--text-sub);
            font-size: 0.85rem;
            border-top: 1px solid #1f2a44;
            padding-top: 25px;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="logo-icon">🛰️ 🪙</div>
            <h1>SATOSHI HUNTER REPORT</h1>
            <p class="subtitle">내 컴퓨터 안에 숨어 있던 잠자는 비트코인 자산 탐지 결과</p>
            <span class="privacy-badge">🔒 내 PC 안에서만 검사했어요 (찾은 내용을 밖으로 보내지 않음) · 확인이 끝나면 이 리포트 파일을 지우세요</span>
        </header>

        <!-- Stats -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">스캔된 총 파일</div>
                <div class="stat-val" style="color: #60a5fa;">__FILES_COUNT__</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">발견된 지갑 파일</div>
                <div class="stat-val" style="color: #ef4444;">__WALLET_COUNT__</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">발견된 시드/니모닉</div>
                <div class="stat-val" style="color: #f7931a;">__MNEMONIC_COUNT__</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">발견된 개인키/주소</div>
                <div class="stat-val" style="color: #10b981;">__KEYS_COUNT__</div>
            </div>
        </div>

        <!-- Section 1: Wallet Files -->
        <div class="section-title">💼 지갑 데이터베이스 및 파일 (__WALLET_COUNT__)</div>
        __WALLET_ITEMS__

        <!-- Section 2: Mnemonics & Keys -->
        <div class="section-title">🔑 시드 구문, 개인키 및 비트코인 주소 (__TEXT_COUNT__)</div>
        __TEXT_ITEMS__

        <footer class="footer">
            <p>Satoshi Hunter v1.0 • Generated on __DATE_TIME__</p>
            <p>※ 주의: 개인키와 시드 구문은 타인에게 절대 노출하지 마세요!</p>
        </footer>
    </div>

    <script>
        function toggleSecret(btn, rawVal) {
            const span = btn.previousElementSibling;
            if (btn.getAttribute('data-shown') === 'true') {
                span.innerText = btn.getAttribute('data-masked');
                btn.innerText = '👁️ 보기';
                btn.setAttribute('data-shown', 'false');
            } else {
                span.innerText = rawVal;
                btn.innerText = '🔒 숨기기';
                btn.setAttribute('data-shown', 'true');
            }
        }
    </script>
</body>
</html>
"""

def generate_html_report(
    files_scanned: int,
    wallet_findings: List[Dict[str, Any]],
    text_findings: List[Dict[str, Any]],
    output_path: str
) -> str:
    """Generates the interactive HTML report file."""
    # Count breakdown
    mnemonic_count = sum(1 for item in text_findings if any(k in item.get("type", "") for k in ("Mnemonic", "시드")))
    keys_count = len(text_findings) - mnemonic_count
    
    # Wallet HTML items
    if wallet_findings:
        wallet_html_blocks = []
        for w in wallet_findings:
            badge_class = "badge-critical" if w.get("confidence") == "CRITICAL" else "badge-high"
            size_kb = f"{w.get('size', 0) / 1024:.1f} KB"
            block = f"""
            <div class="item-card">
                <div class="item-header">
                    <strong>📁 {html.escape(w.get('type', 'Wallet File'))}</strong>
                    <div>
                        <span class="badge {badge_class}">{w.get('confidence', 'HIGH')}</span>
                        <span style="font-size: 0.85rem; color: #9ca3af; margin-left: 8px;">{size_kb}</span>
                    </div>
                </div>
                <div class="item-path">📄 {html.escape(w.get('filepath', ''))}</div>
            </div>
            """
            wallet_html_blocks.append(block)
        wallet_items_rendered = "\n".join(wallet_html_blocks)
    else:
        wallet_items_rendered = '<div class="empty-state">발견된 암호화폐 지갑 데이터베이스 파일이 없습니다.</div>'

    # Text Findings HTML items
    if text_findings:
        text_html_blocks = []
        for item in text_findings:
            val = item.get("value", "")
            val_type = item.get("type", "Crypto")
            conf = item.get("confidence", "HIGH")
            chain = item.get("chain", "")
            badge_class = "badge-critical" if conf == "CRITICAL" else ("badge-high" if conf == "HIGH" else "badge-medium")
            masked = mask_secret(val, val_type)

            explorer_btn = ""
            exp_url = get_explorer_url(val, val_type, chain)
            if exp_url:
                explorer_btn = f'<a class="btn-explorer" href="{html.escape(exp_url)}" target="_blank" rel="noopener">🔍 블록체인 잔액 조회</a>'

            toggle_btn = ""
            if any(k in val_type for k in ("Private Key", "Mnemonic", "개인키", "시드", "Keypair")):
                safe_raw = html.escape(val).replace('"', '&quot;')
                safe_mask = html.escape(masked).replace('"', '&quot;')
                toggle_btn = f'<button class="btn-toggle" data-masked="{safe_mask}" data-shown="false" onclick="toggleSecret(this, \'{safe_raw}\')">👁️ 보기</button>'

            line_info = f" (Line {item['line']})" if "line" in item else ""

            block = f"""
            <div class="item-card">
                <div class="item-header">
                    <strong>⚡ {html.escape(val_type)}{line_info}</strong>
                    <div>
                        <span class="badge {badge_class}">{conf}</span>
                        {explorer_btn}
                    </div>
                </div>
                <div class="item-value">
                    <span>{html.escape(masked)}</span>
                    {toggle_btn}
                </div>
                <div class="item-path">📄 {html.escape(item.get('filepath', ''))}</div>
            </div>
            """
            text_html_blocks.append(block)
        text_items_rendered = "\n".join(text_html_blocks)
    else:
        text_items_rendered = '<div class="empty-state">발견된 비트코인 개인키, 시드 구문 또는 주소가 없습니다.</div>'

    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rendered = HTML_TEMPLATE.replace("__FILES_COUNT__", f"{files_scanned:,}")
    rendered = rendered.replace("__WALLET_COUNT__", str(len(wallet_findings)))
    rendered = rendered.replace("__MNEMONIC_COUNT__", str(mnemonic_count))
    rendered = rendered.replace("__KEYS_COUNT__", str(keys_count))
    rendered = rendered.replace("__TEXT_COUNT__", str(len(text_findings)))
    rendered = rendered.replace("__WALLET_ITEMS__", wallet_items_rendered)
    rendered = rendered.replace("__TEXT_ITEMS__", text_items_rendered)
    rendered = rendered.replace("__DATE_TIME__", now_str)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)

    return output_path
