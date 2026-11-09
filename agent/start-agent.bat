@echo off
chcp 65001 >nul
cd /d "%~dp0.."
echo ==========================================
echo  RemoteMgr local connection agent
echo  Listening on http://127.0.0.1:17860
echo  Keep this window open. Ctrl+C to stop.
echo  服务端地址：优先读 agent\config.json（或 exe 同目录 config.json），
echo  其次环境变量 REMOTEMGR_SERVER，再次内置默认 http://192.168.10.121:8800
echo ==========================================
python agent\remotemgr_agent.py serve --port 17860
echo.
echo Agent stopped. Press any key to close.
pause >nul
