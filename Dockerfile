# syntax=docker/dockerfile:1
FROM node:22-alpine AS frontend
WORKDIR /src
COPY package.json package-lock.json tsconfig.json ./
COPY scripts ./scripts
RUN npm ci --no-audit --no-fund && npm run check-deps
COPY web ./web
RUN npx tsc -p tsconfig.json

FROM golang:1.27-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/web/static/js ./web/static/js
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /tlswatch ./cmd/tlswatch \
 && mkdir -p /data && chown 65532:65532 /data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /tlswatch /tlswatch
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
ENV TLSWATCH_LISTEN=0.0.0.0:8080 TLSWATCH_DB=/data/tlswatch.db
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK NONE
ENTRYPOINT ["/tlswatch"]
CMD ["serve"]
