# syntax=docker/dockerfile:1@sha256:2780b5c3bab67f1f76c781860de469442999ed1a0d7992a5efdf2cffc0e3d769
# Node.js LTS on Wolfi — standard variant (includes shell, npm, npx).
# Use as the build stage in multi-stage Dockerfiles.
FROM cgr.dev/chainguard/node:latest-dev@sha256:54b9908d5fb64107d2de3cf00fdb8f6f9f7b18f9923c63155c551abb743d2293

ARG BUILD_DATE
ARG GIT_REVISION

LABEL org.opencontainers.image.source="https://github.com/platform-images/base-docker-images"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${GIT_REVISION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV NODE_ENV=production \
    NPM_CONFIG_LOGLEVEL=warn \
    NPM_CONFIG_UPDATE_NOTIFIER=false

WORKDIR /app

USER nonroot