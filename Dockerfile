# syntax=docker/dockerfile:1
# Both build stages run on the builder's own platform and cross-compile for
# the target, so a multi-platform build does not run Go under emulation.
FROM --platform=$BUILDPLATFORM node:22-alpine AS frontend
WORKDIR /src
COPY package.json package-lock.json tsconfig.json ./
COPY scripts ./scripts
RUN npm ci --no-audit --no-fund && npm run check-deps
COPY web ./web
RUN npx tsc -p tsconfig.json

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
# The release workflow passes the tag; a local `docker compose up --build`
# passes nothing and gets the version from the checkout (scripts/version.sh),
# which is why .git is in the build context.
ARG VERSION=
# Docker fills these in for the platform being built; TARGETVARIANT is "v7"
# for linux/arm/v7 and empty elsewhere.
ARG TARGETOS TARGETARCH TARGETVARIANT
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN if [ -n "$VERSION" ]; then echo "$VERSION"; else sh scripts/version.sh; fi > /version \
 && echo "building tlswatch $(cat /version)"
COPY --from=frontend /src/web/static/js ./web/static/js
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$(cat /version)" -o /tlswatch ./cmd/tlswatch \
 && mkdir -p /data && chown 65532:65532 /data

FROM scratch
LABEL org.opencontainers.image.source="https://github.com/sjoerd305/tlswatch" \
      org.opencontainers.image.description="Monitors the TLS certificates served on your hosts and alerts before they expire or change" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /tlswatch /tlswatch
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
# TLSWATCH_CONTAINER tells "tlswatch node" it is updated by pulling the image.
ENV TLSWATCH_LISTEN=0.0.0.0:8080 TLSWATCH_DB=/data/tlswatch.db TLSWATCH_CONTAINER=1
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=1m --timeout=10s --start-period=30s CMD ["/tlswatch", "healthcheck"]
ENTRYPOINT ["/tlswatch"]
CMD ["serve"]
