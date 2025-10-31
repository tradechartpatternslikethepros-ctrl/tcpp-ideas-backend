# Dockerfile
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm i --omit=dev; fi

COPY . .

ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "server.cjs"]
