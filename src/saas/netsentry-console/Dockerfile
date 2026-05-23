# Stage 1: Build
FROM node:22-alpine AS builder
WORKDIR /app
COPY src/saas/netsentry-console/package*.json ./
RUN npm install
COPY src/saas/netsentry-console/ .
RUN npm run build

# Stage 2: Serve with nginx
FROM nginx:alpine
COPY --from=builder /app/dist/netsentry-console /usr/share/nginx/html
COPY src/saas/netsentry-console/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
