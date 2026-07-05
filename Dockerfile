# syntax=docker/dockerfile:1.7

FROM node:22-bookworm-slim AS build
WORKDIR /workspace
ENV COREPACK_HOME=/tmp/corepack
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY packages/protocol/package.json packages/protocol/package.json
COPY server/package.json server/package.json
RUN pnpm install --frozen-lockfile

COPY packages packages
COPY server server
COPY admin-ui admin-ui
RUN pnpm build
RUN pnpm --filter @vorcaro/server deploy --prod --legacy /runtime

FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV VORCARO_DATA_DIR=/var/lib/vorcaro
ENV VORCARO_CERT_DIR=/etc/vorcaro/certs
ENV VORCARO_SECRET_DIR=/etc/vorcaro/secrets

RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl \
  && rm -rf /var/lib/apt/lists/* \
  && groupadd --system --gid 10001 vorcaro \
  && useradd --system --uid 10001 --gid vorcaro --home-dir /nonexistent --shell /usr/sbin/nologin vorcaro \
  && mkdir -p /var/lib/vorcaro /etc/vorcaro/certs /etc/vorcaro/secrets \
  && chown -R vorcaro:vorcaro /var/lib/vorcaro

COPY --from=build --chown=vorcaro:vorcaro /runtime /app/server
COPY --from=build --chown=vorcaro:vorcaro /workspace/admin-ui /app/admin-ui

USER vorcaro
EXPOSE 8443 9443
VOLUME ["/var/lib/vorcaro"]
HEALTHCHECK --interval=30s --timeout=8s --start-period=20s --retries=3 CMD ["node", "/app/server/dist/healthcheck.js"]
CMD ["node", "/app/server/dist/main.js"]
