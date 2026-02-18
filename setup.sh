#!/bin/bash
set -e

# setup.sh - Easy Installation Script for Secure Coding Platform

echo "=================================================="
echo "   Secure Coding Platform - Setup Wizard"
echo "=================================================="
echo ""

# 1. Prerequisites Check
echo "[*] Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "Error: docker could not be found. Please install Docker first."
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "Error: python3 could not be found. Please install Python 3 first."
    exit 1
fi

if ! command -v node &> /dev/null; then
    echo "Error: node could not be found. Please install Node.js first."
    exit 1
fi

echo "[+] Prerequisites met."
echo ""

# 2. Environment Setup
echo "[*] Setting up environment configuration..."

if [ ! -f .env ]; then
    echo " -> Copying .env.example to .env..."
    cp .env.example .env
    
    echo " -> Generating secure keys..."
    SECRET_KEY=$(python3 scripts/generate_secrets.py random)
    ENCRYPTION_KEY=$(python3 scripts/generate_secrets.py fernet)
    POSTGRES_PASSWORD=$(python3 scripts/generate_secrets.py random)
    RABBITMQ_DEFAULT_PASS=$(python3 scripts/generate_secrets.py random)
    OPENSEARCH_INITIAL_ADMIN_PASSWORD=$(python3 scripts/generate_secrets.py random)
    
    # Use sed based on OS (macOS sed requires empty extension for -i)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s/SECRET_KEY=supersecretkey1234567890/SECRET_KEY=$SECRET_KEY/" .env
        sed -i '' "s/ENCRYPTION_KEY=.*$/ENCRYPTION_KEY=$ENCRYPTION_KEY/" .env
        sed -i '' "s/POSTGRES_PASSWORD=postgres/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/" .env
        sed -i '' "s/RABBITMQ_DEFAULT_PASS=password/RABBITMQ_DEFAULT_PASS=$RABBITMQ_DEFAULT_PASS/" .env
        sed -i '' "s/OPENSEARCH_INITIAL_ADMIN_PASSWORD=StrongPassword123!/OPENSEARCH_INITIAL_ADMIN_PASSWORD=$OPENSEARCH_INITIAL_ADMIN_PASSWORD/" .env
    else
        sed -i "s/SECRET_KEY=supersecretkey1234567890/SECRET_KEY=$SECRET_KEY/" .env
        sed -i "s/ENCRYPTION_KEY=.*$/ENCRYPTION_KEY=$ENCRYPTION_KEY/" .env
        sed -i "s/POSTGRES_PASSWORD=postgres/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/" .env
        sed -i "s/RABBITMQ_DEFAULT_PASS=password/RABBITMQ_DEFAULT_PASS=$RABBITMQ_DEFAULT_PASS/" .env
        sed -i "s/OPENSEARCH_INITIAL_ADMIN_PASSWORD=StrongPassword123!/OPENSEARCH_INITIAL_ADMIN_PASSWORD=$OPENSEARCH_INITIAL_ADMIN_PASSWORD/" .env
    fi
    
    echo "[+] .env created and configured with new secrets."
else
    echo "[!] .env already exists. Skipping generation to preserve existing config."
fi
echo ""

# 3. Docker Build and Launch
echo "[*] Launching Docker containers (this may take a few minutes)..."
docker compose up -d --build

echo "[*] Waiting for database to be healthy..."
# Simple wait loop for db container
MAX_RETRIES=30
COUNT=0
until [ "$(docker inspect -f '{{.State.Health.Status}}' secure_coding_platform_db 2>/dev/null)" == "healthy" ]; do
    if [ $COUNT -gt $MAX_RETRIES ]; then
        echo "Error: Database failed to become healthy in time."
        exit 1
    fi
    printf "."
    sleep 2
    COUNT=$((COUNT+1))
done
echo ""
echo "[+] Database is healthy."
echo ""

# 4. Database Migrations & Initial Data
echo "[*] Applying database migrations..."
docker compose exec app alembic upgrade head

echo "[*] Ensuring default superuser exists..."
# We use a specific script or just ensure the admin logic runs
docker compose exec app python /app/scripts/create_superuser.py

echo "[+] Database initialized."
echo ""

# 5. UI Installation
echo "[*] Installing UI dependencies..."
cd secure-code-ui
npm install
cd ..
echo "[+] UI dependencies installed."
echo ""

echo "=================================================="
echo "   Setup Complete!"
echo "=================================================="
echo ""
echo "Access the application at:"
echo "   -> http://localhost:5173"
echo ""
echo "Access Grafana at:"
echo "   -> http://localhost:3000"
echo ""
echo "To start the UI development server, run:"
echo "   cd secure-code-ui && npm run dev"
echo ""
