#!/bin/sh

DOMAIN="${VITE_ALLOWED_HOSTS:-secure.nerdykrishna.com}"
EMAIL="admin@secure.nerdykrishna.com"

echo "Checking SSL certificates for $DOMAIN..."

if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    echo "No SSL certificate found. Bootstrapping HTTP-only configuration..."
    cp /etc/nginx/nginx-http.conf /etc/nginx/conf.d/default.conf
    
    # Start Nginx in background to respond to ACME challenges
    echo "Starting temporary Nginx layer..."
    nginx -g "daemon off;" &
    NGINX_PID=$!
    
    # Wait for Nginx to boot
    sleep 3
    
    echo "Requesting Let's Encrypt certificate for $DOMAIN..."
    certbot certonly --webroot -w /usr/share/nginx/html -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL"
    
    # Stop temporary Nginx
    kill $NGINX_PID
    wait $NGINX_PID 2>/dev/null
    
    if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        echo "Certificate successfully generated! Switching to HTTPS configuration."
        cp /etc/nginx/nginx-https.conf /etc/nginx/conf.d/default.conf
    else
        echo "WARNING: Failed to retrieve certificate for $DOMAIN. Falling back to HTTP-only mode."
        echo "Note: If running locally or without DNS configured, this is expected."
        # Leaves HTTP conf in place
    fi
else
    echo "SSL certificate found! Booting directly in HTTPS mode."
    cp /etc/nginx/nginx-https.conf /etc/nginx/conf.d/default.conf
fi

# Start a background process for certbot renewal (checks twice daily as recommended)
(
    while true; do
        sleep 12h
        certbot renew --quiet --post-hook "nginx -s reload"
    done
) &

# The main Nginx process will start after this entrypoint script finishes.
exit 0
