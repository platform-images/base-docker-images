# syntax=docker/dockerfile:1
# Wolfi OS base — the foundation all other images build from.
# Pin updated weekly by Renovate. Run `make scan IMAGE=wolfi-base` to verify CVE count.
FROM cgr.dev/chainguard/wolfi-base:latest@sha256:3258be472764337fd13095bcbb3182da170243b5819fd67ad4c0754590588b31

ARG BUILD_DATE
ARG GIT_REVISION

LABEL org.opencontainers.image.source="https://github.com/platform-images/base-docker-images"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${GIT_REVISION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache \
    ca-certificates \
    tzdata

USER nonroot