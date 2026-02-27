@echo off

:: setup.bat - Easy Installation Script for Secure Coding Platform

echo ==================================================
echo    Secure Coding Platform - Setup Wizard
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
    for /f "delims=" %%i in ('python scripts/generate_secrets.py random') do set OPENSEARCH_INITIAL_ADMIN_PASSWORD=%%i

    :: PowerShell is easiest for replacement on Windows without external tools like sed
    powershell -Command "(Get-Content .env) -replace 'SECRET_KEY=supersecretkey1234567890', 'SECRET_KEY=%SECRET_KEY%' | Set-Content .env"
    powershell -Command "(Get-Content .env) -replace 'ENCRYPTION_KEY=.*', 'ENCRYPTION_KEY=%ENCRYPTION_KEY%' | Set-Content .env"
    powershell -Command "(Get-Content .env) -replace 'POSTGRES_PASSWORD=postgres', 'POSTGRES_PASSWORD=%POSTGRES_PASSWORD%' | Set-Content .env"
    powershell -Command "(Get-Content .env) -replace 'RABBITMQ_DEFAULT_PASS=password', 'RABBITMQ_DEFAULT_PASS=%RABBITMQ_DEFAULT_PASS%' | Set-Content .env"
    powershell -Command "(Get-Content .env) -replace 'OPENSEARCH_INITIAL_ADMIN_PASSWORD=StrongPassword123!', 'OPENSEARCH_INITIAL_ADMIN_PASSWORD=%OPENSEARCH_INITIAL_ADMIN_PASSWORD%' | Set-Content .env"
    
    echo [+] .env created and configured with new secrets.
) else (
    echo [!] .env already exists. Skipping generation.
)
echo.

:: 2.5 Deployment Configuration Prompt
echo [*] Deployment Configuration
set /p DEPLOYMENT_TYPE="Are you deploying this locally for testing or on a cloud server? (local/cloud) "
echo.

:: Always save deployment type
powershell -Command "(Get-Content .env) -replace '^DEPLOYMENT_TYPE=.*', '' | Set-Content .env"
echo DEPLOYMENT_TYPE=%DEPLOYMENT_TYPE%>> .env

set ENABLE_SSL=N
if /i "%DEPLOYMENT_TYPE%"=="cloud" (
    set /p ENABLE_SSL="Would you like to auto-provision a free SSL Certificate for a custom domain? (y/n) "
    echo.
)

if /i "%ENABLE_SSL%"=="y" (
    set /p SSL_DOMAIN="Please enter your domain name (e.g., secure.nerdykrishna.com): "
    
    powershell -Command "(Get-Content .env) -replace '^SSL_ENABLED=.*', '' | Set-Content .env"
    echo SSL_ENABLED=true>> .env
    
    powershell -Command "(Get-Content .env) -replace '^SSL_DOMAIN=.*', '' | Set-Content .env"
    call echo SSL_DOMAIN=%%SSL_DOMAIN%%>> .env
    
    call echo [+] SSL configuration saved. The UI container will request a certificate for %%SSL_DOMAIN%% on boot.
) else (
    powershell -Command "(Get-Content .env) -replace '^SSL_ENABLED=.*', '' | Set-Content .env"
    echo SSL_ENABLED=false>> .env
    
    if /i "%DEPLOYMENT_TYPE%"=="cloud" (
        echo [-] SSL skipped. The application will be accessible via IP address on HTTP (Port 80).
    ) else (
        echo [-] Local deployment selected. SSL skipped. The application will run on HTTP (Port 80) only.
    )
)
echo.

:: 3. Docker Build and Launch
echo [*] Launching Docker containers...
docker compose up -d --build

echo [*] Waiting for database to be healthy...
:wait_loop
timeout /t 2 /nobreak >nul
for /f "tokens=*" %%i in ('docker inspect -f "{{.State.Health.Status}}" secure_coding_platform_db') do set DB_STATUS=%%i
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
echo    http://localhost:5173
echo.
echo Access Grafana at:
echo    http://localhost:3000
echo.
echo To start the UI development server, run:
echo    cd secure-code-ui ^&^& npm run dev
echo.
pause
