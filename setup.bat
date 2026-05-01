@echo off

:: setup.bat - Easy Installation Script for SCCAP
::
:: SECURITY NOTICE (V15.1.5 - Dangerous Functionality Documentation):
:: This script shells out to PowerShell with operator-supplied values
:: interpolated directly into -replace arguments (see the powershell -Command
:: calls below). Operators with terminal access can therefore inject arbitrary
:: PowerShell expressions through the SSL_DOMAIN prompt (STATE_3) and through
:: any other user-controlled variable passed into those calls.
::
:: Dangerous-functionality surface areas:
::   - Lines 49-52: secret values from generate_secrets.py interpolated into
::     PowerShell -replace strings (trust boundary: script execution context)
::   - Lines 165-174: SSL_DOMAIN and other config values interpolated into
::     PowerShell -replace strings (trust boundary: operator terminal input)
::
:: Domain input is validated with a strict allow-list regex (STATE_3) to
:: block PowerShell metacharacters. Secret values come from generate_secrets.py
:: and should not contain special characters, but are not separately sanitised
:: here. Hardening the interpolation further is tracked as a follow-up.
::

echo ==================================================
echo    SCCAP - Setup Wizard
echo ==================================================
echo.

:: 1. Prerequisites Check
echo [*] Checking prerequisites...

where docker >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: docker could not be found. Please install Docker first.
    exit /b 1
)

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: python could not be found. Please install Python first.
    exit /b 1
)

where node >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: node could not be found. Please install Node.js first.
    exit /b 1
)

echo [+] Prerequisites met.
echo.

:: 2. Environment Setup
echo [*] Setting up environment configuration...

:: NOTE (V15.4.2): Use atomic create via 'copy /-y' to eliminate the TOCTOU
:: (time-of-check/time-of-use) race window between the existence test and
:: file creation. If two concurrent invocations both see the file as missing
:: they would each regenerate secrets, leaving a .env whose secrets do not
:: match what was last echoed to the operator. The 'copy /-y' command fails
:: (errorlevel 1) if .env already exists, making the create atomic.
:: Concurrent invocations of setup.bat are not supported.
copy /-y .env.example .env >nul 2>&1
if %errorlevel% equ 0 (
    echo  -> Copied .env.example to .env...

    echo  -> Generating secure keys...
    :: We use python to get the secrets, capturing output to variables
    for /f "delims=" %%i in ('python scripts/generate_secrets.py random') do set SECRET_KEY=%%i
    for /f "delims=" %%i in ('python scripts/generate_secrets.py fernet') do set ENCRYPTION_KEY=%%i
    for /f "delims=" %%i in ('python scripts/generate_secrets.py random') do set POSTGRES_PASSWORD=%%i
    for /f "delims=" %%i in ('python scripts/generate_secrets.py random') do set RABBITMQ_DEFAULT_PASS=%%i

    :: DANGEROUS SURFACE (V15.1.5): secret values from generate_secrets.py are
    :: interpolated into PowerShell -replace strings below. See header comment.
    :: PowerShell is easiest for replacement on Windows without external tools like sed
    powershell -Command "(Get-Content .env) -replace 'SECRET_KEY=supersecretkey1234567890', 'SECRET_KEY=%SECRET_KEY%' | Set-Content .env"
    powershell -Command "(Get-Content .env) -replace 'ENCRYPTION_KEY=.*', 'ENCRYPTION_KEY=%ENCRYPTION_KEY%' | Set-Content .env"
    powershell -Command "(Get-Content .env) -replace 'POSTGRES_PASSWORD=postgres', 'POSTGRES_PASSWORD=%POSTGRES_PASSWORD%' | Set-Content .env"
    powershell -Command "(Get-Content .env) -replace 'RABBITMQ_DEFAULT_PASS=password', 'RABBITMQ_DEFAULT_PASS=%RABBITMQ_DEFAULT_PASS%' | Set-Content .env"

    echo [+] .env created and configured with new secrets.
) else (
    echo [!] .env already exists. Skipping generation.
)
echo.

:: 2.5 Deployment Configuration Options
echo [*] Deployment Configuration Options:

set DEPLOYMENT_TYPE=
set SSL_ENABLED=false
set SSL_DOMAIN=

:STATE_1
echo.
echo Select Deployment Environment:
echo   1) Local (Testing/Development)
echo   2) Cloud (Production Server)
echo   0) Exit Setup
set /p CHOICE="Your choice (1/2/0): "
if "%CHOICE%"=="1" (
    set DEPLOYMENT_TYPE=local
    set SSL_ENABLED=false
    goto STATE_4
)
if "%CHOICE%"=="2" (
    set DEPLOYMENT_TYPE=cloud
    goto STATE_2
)
if "%CHOICE%"=="0" (
    echo Setup cancelled.
    exit /b 0
)
echo Invalid choice. Please enter 1, 2, or 0.
goto STATE_1

:STATE_2
echo.
echo Would you like to auto-provision a free Let's Encrypt SSL Certificate?
echo   1) Yes (I have a valid domain pointing to this server's IP)
echo   2) No - PLAINTEXT HTTP only (NOT recommended for production)
echo   0) Go Back
set /p CHOICE="Your choice (1/2/0): "
if "%CHOICE%"=="1" (
    set SSL_ENABLED=true
    goto STATE_3
)
if "%CHOICE%"=="2" (
    goto STATE_2_CONFIRM_PLAINTEXT
)
if "%CHOICE%"=="0" (
    goto STATE_1
)
echo Invalid choice. Please enter 1, 2, or 0.
goto STATE_2

:STATE_2_CONFIRM_PLAINTEXT
echo.
echo WARNING: Cloud deployments without TLS transmit all data - including
echo credentials and sensitive code - in cleartext over the public Internet.
echo This violates security best practices and is strongly discouraged.
echo.
echo To confirm you understand and accept this risk, type exactly:
echo   YES_I_UNDERSTAND_PLAINTEXT
echo Or press Enter to go back and enable SSL.
echo.
set /p CONFIRM_PLAINTEXT="Your confirmation: "
if "%CONFIRM_PLAINTEXT%"=="YES_I_UNDERSTAND_PLAINTEXT" (
    set SSL_ENABLED=false
    goto STATE_4
)
echo Confirmation not accepted. Returning to SSL configuration.
goto STATE_2

:STATE_3
echo.
set /p CHOICE="Please enter your domain name/IP (e.g., app.yourdomain.com) [or type '0' to go back]: "
if "%CHOICE%"=="0" (
    goto STATE_2
)
if "%CHOICE%"=="" (
    echo Domain cannot be blank. Please provide a valid domain or IP.
    goto STATE_3
)
:: V02.2.1: Validate domain against a strict allow-list of hostname/IPv4 characters.
:: Only letters, digits, dots, and hyphens are permitted. This blocks PowerShell
:: metacharacters (quotes, backticks, $, |, &, newline) from reaching the
:: 'powershell -Command' calls at lines 165-174 (DANGEROUS SURFACE, V15.1.5).
echo %CHOICE%| findstr /R /B /E "^[A-Za-z0-9][A-Za-z0-9.\-]*[A-Za-z0-9]$" >nul
if errorlevel 1 (
    echo Invalid domain. Use only letters, digits, dots, and hyphens.
    echo Example: app.yourdomain.com or 203.0.113.10
    goto STATE_3
)
set SSL_DOMAIN=%CHOICE%
goto STATE_4

:STATE_4
echo.
echo Please confirm your configuration:
echo -----------------------------------
if "%DEPLOYMENT_TYPE%"=="local" (
    echo Environment: Local Testing
    echo SSL Mode:    Disabled ^(Port 80^)
) else (
    echo Environment: Cloud Deployment
    if "%SSL_ENABLED%"=="true" (
        echo SSL Mode:    Enabled via Let's Encrypt
        echo Domain:      %SSL_DOMAIN%
    ) else (
        echo SSL Mode:    Disabled ^(Port 80 via IP^)
    )
)
echo -----------------------------------
echo   1) Proceed with Setup
echo   0) Go Back to change settings
set /p CHOICE="Your choice (1/0): "

if "%CHOICE%"=="1" (
    goto SAVE_CONFIG
)
if "%CHOICE%"=="0" (
    if "%DEPLOYMENT_TYPE%"=="local" (
        goto STATE_1
    )
    if "%SSL_ENABLED%"=="false" (
        goto STATE_2
    )
    goto STATE_3
)
echo Invalid choice. Please enter 1 or 0.
goto STATE_4

:SAVE_CONFIG
echo.
echo [*] Saving Configuration...

:: V12.2.1: Refuse to write .env for cloud deployments without TLS unless the
:: operator explicitly confirmed plaintext (CONFIRM_PLAINTEXT check above).
:: This guard is a belt-and-suspenders check; the STATE_2 gate is the primary.
if "%DEPLOYMENT_TYPE%"=="cloud" (
    if "%SSL_ENABLED%"=="false" (
        if not "%CONFIRM_PLAINTEXT%"=="YES_I_UNDERSTAND_PLAINTEXT" (
            echo.
            echo ERROR: Cloud deployments must terminate TLS.
            echo Re-run setup with a domain pointing at this server to enable SSL,
            echo or use Local mode for testing.
            exit /b 1
        )
    )
)

:: DANGEROUS SURFACE (V15.1.5): operator-supplied SSL_DOMAIN and other config
:: values are interpolated into PowerShell -replace strings below. See header
:: comment. SSL_DOMAIN is validated by STATE_3 allow-list regex before reaching
:: this point, blocking PowerShell metacharacters.
powershell -Command "(Get-Content .env) -replace '^DEPLOYMENT_TYPE=.*', '' | Set-Content .env"
echo DEPLOYMENT_TYPE=%DEPLOYMENT_TYPE%>> .env

powershell -Command "(Get-Content .env) -replace '^SSL_ENABLED=.*', '' | Set-Content .env"
echo SSL_ENABLED=%SSL_ENABLED%>> .env

powershell -Command "(Get-Content .env) -replace '^SSL_DOMAIN=.*', '' | Set-Content .env"
if not "%SSL_DOMAIN%"=="" (
    echo SSL_DOMAIN=%SSL_DOMAIN%>> .env
)
echo [+] Configuration saved.
echo.

:: 3. Docker Build and Launch
echo [*] Launching Docker containers...
docker compose up -d --build

echo [*] Waiting for database to be healthy...
:wait_loop
timeout /t 2 /nobreak >nul
for /f "tokens=*" %%i in ('docker inspect -f "{{.State.Health.Status}}" sccap_db') do set DB_STATUS=%%i
if "%DB_STATUS%"=="healthy" goto db_healthy
echo  ...waiting for db...
goto wait_loop

:db_healthy
echo [+] Database is healthy.
echo.

:: 4. Database Migrations
echo [*] Applying database migrations...
docker compose exec app alembic upgrade head

echo [+] Database initialized. Proceed to the Web UI to create your Admin Superuser.
echo.

:: 5. UI Installation
echo [*] Installing UI dependencies...
cd secure-code-ui
call npm install
cd ..
echo [+] UI dependencies installed.
echo.

echo ==================================================
echo    Setup Complete!
echo ==================================================
echo.
echo Access the application at:
if "%DEPLOYMENT_TYPE%"=="local" (
    echo    http://localhost ^(Production build via Docker^)
    echo    http://localhost:5173 ^(If running UI dev server^)
) else (
    if "%SSL_ENABLED%"=="true" (
        echo    https://%SSL_DOMAIN%
    ) else (
        echo    NOTE: SSL is not enabled. Access via your server's IP on port 80.
        echo    Configure SSL ^(re-run setup with a domain^) before exposing this
        echo    server to the public Internet to avoid transmitting data in cleartext.
    )
)
echo.
echo Access Grafana at:
if "%DEPLOYMENT_TYPE%"=="local" (
    echo    http://localhost:3000
) else (
    if "%SSL_ENABLED%"=="true" (
        echo    https://%SSL_DOMAIN%:3000 ^(route via your reverse proxy^)
        echo    NOTE: Ensure Grafana is fronted by the same nginx+certbot TLS
        echo    termination as the app, or accessed via a Tailscale/SSH tunnel.
    ) else (
        echo    Grafana is not exposed publicly - tunnel via SSH to localhost:3000
        echo    or use: docker compose exec grafana ...
        echo    Do not expose Grafana over plaintext HTTP on the public Internet.
    )
)
echo.
echo To start the UI development server, run:
echo    cd secure-code-ui ^&^& npm run dev
echo.
pause
