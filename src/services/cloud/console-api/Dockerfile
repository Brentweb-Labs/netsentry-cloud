FROM node:22-alpine AS builder
WORKDIR /app
COPY src/services/cloud/console-api/package*.json ./
RUN npm ci
COPY src/services/cloud/console-api/ .
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
USER node
EXPOSE 8095
CMD ["node", "dist/main"]
