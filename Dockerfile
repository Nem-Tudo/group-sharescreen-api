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

# Runs tsx directly as PID 1 rather than `npm start` — npm wraps the script
# in a `sh -c` child process that does not reliably forward SIGTERM to it,
# which meant Kubernetes' rollout signal never reached the graceful-shutdown
# handler in server/index.ts. Confirmed with a manual SIGTERM test: killing
# the `npm start` process left the underlying tsx/node process (and every
# open WebSocket) running untouched.
CMD ["node_modules/.bin/tsx", "server/index.ts"]
