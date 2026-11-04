# Mandat MCP Scanner (mandat web) for Fly.io or any container host.
# Stage 1 builds dist/ from source; stage 2 contains only dist/ (Mandat has no runtime dependencies).
# The base image is pinned by digest (node:24-alpine, 2026-10-28). Bump deliberately.

FROM node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85 AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY scripts ./scripts
COPY src ./src
RUN node scripts/build.ts

FROM node:24-alpine@sha256:8a32c8cf649a49915a66e81e7a609223c708d0adabf288ee3f4077d765542f85
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY package.json LICENSE ./
USER node
EXPOSE 8080
# Public mode: private/internal addresses are refused. Fly's proxy sets Fly-Client-IP for rate limiting.
CMD ["node", "dist/cli/bin.js", "web", "--host", "0.0.0.0", "--port", "8080", "--client-ip-header", "fly-client-ip"]
