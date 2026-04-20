@echo off

:: setup.bat - Easy Installation Script for SCCAP

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

if not exist .env (
    echo  -> Copying .env.example to .env...
    copy .env.example .env >nul
    
    echo  -> Generating secure keys...
    :: We use python to get the secrets, capturing output to variables
    for /f "delims=" %%i in ('python scripts/generate_secrets.py random') do set SECRET_KEY=%%i
    for /f "delims=" %%i in ('python scripts/generate_secrets.py fernet') do set ENCRYPTION_KEY=%%i
    for /f "delims=" %%i in ('python scripts/generate_secrets.py random') do set POSTGRES_PASSWORD=%%i
    for /f "delims=" %%i in ('python scripts/generate_secrets.py random') do set RABBITMQ_DEFAULT_PASS=%%i

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
echo   2) No (I will access via IP or configure SSL manually)
echo   0) Go Back
set /p CHOICE="Your choice (1/2/0): "
if "%CHOICE%"=="1" (
    set SSL_ENABLED=true
    goto STATE_3
)
if "%CHOICE%"=="2" (
    set SSL_ENABLED=false
    goto STATE_4
)
if "%CHOICE%"=="0" (
    goto STATE_1
)
echo Invalid choice. Please enter 1, 2, or 0.
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

:: Always save deployment type
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
        echo    http://^<YOUR_SERVER_PUBLIC_IP^>
    )
)
echo.
echo Access Grafana at:
if "%DEPLOYMENT_TYPE%"=="local" (
    echo    http://localhost:3000
) else (
    if "%SSL_ENABLED%"=="true" (
        echo    http://%SSL_DOMAIN%:3000
    ) else (
        echo    http://^<YOUR_SERVER_PUBLIC_IP^>:3000
    )
)
echo.
echo To start the UI development server, run:
echo    cd secure-code-ui ^&^& npm run dev
echo.
pause
