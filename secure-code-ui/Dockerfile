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

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
