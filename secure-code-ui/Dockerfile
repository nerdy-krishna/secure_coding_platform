# Stage 1: Build the React application
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Pass environment variables needed during build
ARG VITE_API_BASE_URL
ARG VITE_ALLOWED_HOSTS
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
ENV VITE_ALLOWED_HOSTS=${VITE_ALLOWED_HOSTS}

RUN npm run build

# Stage 2: Serve with Nginx
FROM nginx:alpine

# Install certbot to allow self-healing SSL certificates
RUN apk add --no-cache certbot

COPY --from=builder /app/dist /usr/share/nginx/html

# We remove the base copy of nginx.conf, and instead copy our dual HTTP/HTTPS templates
COPY nginx-http.conf /etc/nginx/nginx-http.conf
COPY nginx-https.conf /etc/nginx/nginx-https.conf

# Add our entrypoint script for auto-provisioning
COPY nginx-entrypoint.sh /docker-entrypoint.d/99-ssl-setup.sh
RUN chmod +x /docker-entrypoint.d/99-ssl-setup.sh

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
