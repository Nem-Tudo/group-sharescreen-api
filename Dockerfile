# syntax=docker/dockerfile:1

FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=4000

COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json ./
COPY tsconfig.json ./
COPY server ./server

# server/signaling.ts persists chat history under server/data/rooms
RUN mkdir -p server/data/rooms \
  && addgroup -S app && adduser -S app -G app \
  && chown -R app:app /app
USER app

EXPOSE 4000

CMD ["npm", "start"]
