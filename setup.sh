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
    echo "[+] .env created and configured with new secrets."
else
    echo "[!] .env already exists. Preserving existing secrets."
fi

# 2.5. Deployment Configuration Prompt
echo ""
echo "[*] Deployment Configuration Options:"

STATE=1
DEPLOYMENT_TYPE=""
SSL_ENABLED="false"
SSL_DOMAIN=""

while true; do
    case $STATE in
        1)
            echo ""
            echo "Select Deployment Environment:"
            echo "  1) Local (Testing/Development)"
            echo "  2) Cloud (Production Server)"
            echo "  0) Exit Setup"
            read -p "Your choice (1/2/0): " choice
            if [ "$choice" = "1" ]; then
                DEPLOYMENT_TYPE="local"
                SSL_ENABLED="false"
                STATE=4
            elif [ "$choice" = "2" ]; then
                DEPLOYMENT_TYPE="cloud"
                STATE=2
            elif [ "$choice" = "0" ]; then
                echo "Setup cancelled."
                exit 0
            else
                echo "Invalid choice. Please enter 1, 2, or 0."
            fi
            ;;
        2)
            echo ""
            echo "Would you like to auto-provision a free Let's Encrypt SSL Certificate?"
            echo "  1) Yes (I have a valid domain pointing to this server's IP)"
            echo "  2) No (I will access via IP or configure SSL manually)"
            echo "  0) Go Back"
            read -p "Your choice (1/2/0): " choice
            if [ "$choice" = "1" ]; then
                SSL_ENABLED="true"
                STATE=3
            elif [ "$choice" = "2" ]; then
                SSL_ENABLED="false"
                STATE=4
            elif [ "$choice" = "0" ]; then
                STATE=1
            else
                echo "Invalid choice. Please enter 1, 2, or 0."
            fi
            ;;
        3)
            echo ""
            read -p "Please enter your domain name/IP (e.g., example.com or 192.168.1.100) [or type '0' to go back]: " choice
            if [ "$choice" = "0" ]; then
                STATE=2
            elif [ -z "$choice" ]; then
                echo "Domain cannot be blank. Please provide a valid domain or IP."
            else
                SSL_DOMAIN="$choice"
                STATE=4
            fi
            ;;
        4)
            echo ""
            echo "Please confirm your configuration:"
            echo "-----------------------------------"
            if [ "$DEPLOYMENT_TYPE" = "local" ]; then
                echo "Environment: Local Testing"
                echo "SSL Mode:    Disabled (Port 80)"
            else
                echo "Environment: Cloud Deployment"
                if [ "$SSL_ENABLED" = "true" ]; then
                    echo "SSL Mode:    Enabled via Let's Encrypt"
                    echo "Domain:      $SSL_DOMAIN"
                else
                    echo "SSL Mode:    Disabled (Port 80 via IP)"
                fi
            fi
            echo "-----------------------------------"
            echo "  1) Proceed with Setup"
            echo "  0) Go Back to change settings"
            read -p "Your choice (1/0): " choice
            
            if [ "$choice" = "1" ]; then
                break
            elif [ "$choice" = "0" ]; then
                if [ "$DEPLOYMENT_TYPE" = "local" ] || [ "$SSL_ENABLED" = "false" ]; then
                    STATE=1
                else
                    STATE=3
                fi
            else
                echo "Invalid choice. Please enter 1 or 0."
            fi
            ;;
    esac
done

echo ""
echo "[*] Saving Configuration..."
if grep -q "^DEPLOYMENT_TYPE=" .env; then
    sed -i.bak "s/^DEPLOYMENT_TYPE=.*/DEPLOYMENT_TYPE=$DEPLOYMENT_TYPE/" .env
else
    echo "DEPLOYMENT_TYPE=$DEPLOYMENT_TYPE" >> .env
fi

if grep -q "^SSL_ENABLED=" .env; then
    sed -i.bak "s/^SSL_ENABLED=.*/SSL_ENABLED=$SSL_ENABLED/" .env
else
    echo "SSL_ENABLED=$SSL_ENABLED" >> .env
fi

if grep -q "^SSL_DOMAIN=" .env; then
    sed -i.bak "s/^SSL_DOMAIN=.*/SSL_DOMAIN=$SSL_DOMAIN/" .env
else
    if [ ! -z "$SSL_DOMAIN" ]; then
        echo "SSL_DOMAIN=$SSL_DOMAIN" >> .env
    fi
fi
rm -f .env.bak
echo "[+] Configuration saved."


# 2. Environment Setup (Cont.)
# CORS Configuration is now handled in the Setup Wizard UI.


# 3. Docker Build and Launch
echo "[*] Launching Docker containers (this may take a few minutes)..."
# We need to ensure the VITE variables are available to the build context
# Sourcing .env is one way, but docker compose reads .env automatically
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

echo "[+] Database initialized. Proceed to the Web UI to create your Admin Superuser."
echo ""

echo "[+] Database initialized."
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
