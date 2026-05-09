# syntax=docker/dockerfile:1.7

# ── deps ──────────────────────────────────────────────────────────────────────
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
# `npm install` rather than `npm ci`: vitest pulls in platform-specific
# optional deps (esbuild, oxc, @emnapi/runtime) that npm only records in
# the lock file for the host that ran `npm install`. Strict `npm ci`
# rejects the linux container build when the lock was generated on macOS.
# `npm install` is functionally equivalent here — same package.json, same
# resolved versions, just permissive about the gap.
RUN npm install --no-audit --no-fund

# ── build ─────────────────────────────────────────────────────────────────────
FROM node:22-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ── runtime ───────────────────────────────────────────────────────────────────
FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
# 9120 (not the Next.js default 3000) to avoid colliding with the dozen
# other dev servers operators have running locally. Mirrors compose
# port mapping. Sits next to the engine on 9119.
ENV PORT=9120
ENV HOSTNAME=0.0.0.0

# node:22-alpine ships a `node` user (uid 1000, gid 1000) — reuse it
# instead of creating a colliding `app` user.
USER node

COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
COPY --from=build --chown=node:node /app/public ./public

EXPOSE 9120
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD wget -qO- http://localhost:9120 || exit 1

CMD ["node", "server.js"]
