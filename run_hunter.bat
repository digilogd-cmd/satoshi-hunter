@echo off
chcp 65001 > nul
title Satoshi Hunter
color 0E
cd /d "%~dp0"
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
