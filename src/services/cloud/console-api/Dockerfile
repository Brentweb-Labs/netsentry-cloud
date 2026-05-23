FROM node:22-alpine AS builder
WORKDIR /app
COPY src/services/cloud/console-api/package*.json ./
RUN npm install
COPY src/services/cloud/console-api/ .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
EXPOSE 8095
CMD ["node", "dist/main"]
