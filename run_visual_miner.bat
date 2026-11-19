@echo off
chcp 65001 > nul
title Satoshi Hunter - Visual Miner
color 0E
cd /d "%~dp0"
echo ===============================================================
echo   사토시 헌터 - 광부 로봇 화면
echo   광부 화면은 연출(데모)입니다. 실제 검사는 이 검은 창에서 합니다.
echo ===============================================================
start "" "%~dp0satoshi_hunter\visual_miner.html"
echo.
echo  [1] 브라우저에 광부 화면을 열었습니다.
echo  [2] 내 컴퓨터 검사를 시작하려면 아무 키나 누르세요. (그만두려면 이 창을 닫으세요)
echo ===============================================================
pause > nul
set PY=
where py >nul 2>nul && set PY=py -3
if not defined PY (where python >nul 2>nul && set PY=python)
if not defined PY (
  echo.
  echo  [!] 파이썬이 설치되어 있지 않습니다.
  echo      python.org 에서 파이썬을 설치한 뒤 다시 실행해 주세요.
  echo      설치할 때 첫 화면 아래의 "Add python.exe to PATH" 칸을 꼭 체크하세요.
  echo.
  start "" https://www.python.org/downloads/
  pause
  exit /b
)
%PY% -m satoshi_hunter.hunter
pause
