@echo off
setlocal
cd /d "%~dp0"

set "RHEL_OPS_DEMO=1"
set "RHEL_OPS_NO_AUTH=1"
set "RHEL_OPS_DATA_DIR=%TEMP%\rhel-ops-agent-demo"
set "PYTHONIOENCODING=utf-8"

if exist ".env.windows" (
  for /f "usebackq eol=# tokens=1,* delims==" %%A in (".env.windows") do (
    echo %%A | findstr /b /i "RHEL_OPS_LLM_" >nul
    if not errorlevel 1 set "%%A=%%B"
  )
)

if defined RHEL_AGENT_PORT (
  set "DEMO_PORT=%RHEL_AGENT_PORT%"
) else (
  for /f "usebackq delims=" %%P in (`powershell -NoProfile -Command "$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback,0);$l.Start();$p=([System.Net.IPEndPoint]$l.LocalEndpoint).Port;$l.Stop();$p"`) do set "DEMO_PORT=%%P"
)
if not defined DEMO_PORT set "DEMO_PORT=18877"

echo Starting RHEL Ops Agent demo on http://127.0.0.1:%DEMO_PORT%
echo This demo never executes real system commands.
if "%RHEL_OPS_LLM_ENABLED%"=="1" (
  echo LLM: Qwen API enabled for intent understanding.
) else (
  echo LLM: disabled, using local rules only.
)
echo Press Ctrl+C to stop.
if not defined RHEL_AGENT_NO_BROWSER start "" "http://127.0.0.1:%DEMO_PORT%"

if defined RHEL_AGENT_PYTHON goto use_override
py -3 -c "import sys" >nul 2>nul
if not errorlevel 1 (
  set "PYTHON_CMD=py -3"
  goto use_standard
)
python -c "import sys" >nul 2>nul
if errorlevel 1 goto no_python
set "PYTHON_CMD=python"

:use_standard
%PYTHON_CMD% app.py web --port %DEMO_PORT%
goto end

:use_override
"%RHEL_AGENT_PYTHON%" app.py web --port %DEMO_PORT%
goto end

:no_python
echo.
echo Python 3.9 or newer was not found.
echo Install Python from https://www.python.org/downloads/
echo or open README.md to view the screenshots and setup instructions.
pause

:end
endlocal
