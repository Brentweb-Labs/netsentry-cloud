FROM node:22-bookworm-slim AS builder
WORKDIR /app

COPY src/tools/dashboard/package*.json ./
RUN npm install --include=optional

COPY src/tools/dashboard/. .
RUN npm run build -- --configuration production

FROM nginx:1.28-alpine
COPY --from=builder /app/dist/idps-dashboard/browser /usr/share/nginx/html
COPY src/tools/dashboard/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
