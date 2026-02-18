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

echo [*] Ensuring default superuser exists...
docker compose exec app python scripts/create_superuser.py

echo [+] Database initialized.
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
