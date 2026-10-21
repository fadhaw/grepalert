# Multi-stage build. Pick a binary with --target:
#   docker build --target agent -t grepalert-agent .
#   docker build --target dashboard -t grepalert-dashboard .
ARG GO_VERSION=1.27.3

# The dashboard's web UI, embedded into its binary. It is the same for every
# platform, so it is built once, on the build machine's own architecture.
FROM --platform=$BUILDPLATFORM node:22-alpine AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# Go cross-compiles natively for each target platform (no emulation), so
# multi-arch images (linux/amd64, linux/arm64) build fast.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/internal/dashboard/web/dist ./internal/dashboard/web/dist
ARG VERSION=dev
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/fadhaw/grepalert/internal/version.Version=${VERSION}" \
      -o /out/ ./cmd/... ./examples/compose/webhook-sink ./examples/loadtest/loadgen

FROM alpine:3.22 AS agent
RUN apk add --no-cache tzdata
COPY --from=build /out/grepalert-agent /usr/local/bin/
# A default config driven by environment variables; mount your own over it.
COPY examples/container/agent.yaml /etc/grepalert/agent.yaml
VOLUME /var/lib/grepalert
EXPOSE 9300
HEALTHCHECK --interval=10s --timeout=3s CMD wget -qO- http://127.0.0.1:9300/healthz || exit 1
ENTRYPOINT ["grepalert-agent"]
CMD ["-config", "/etc/grepalert/agent.yaml"]

# Demo only: receives webhooks and serves a rules file as a stand-in for git.
FROM alpine:3.22 AS webhook-sink
COPY --from=build /out/webhook-sink /usr/local/bin/
EXPOSE 9599
ENTRYPOINT ["webhook-sink"]

FROM alpine:3.22 AS dashboard
RUN apk add --no-cache tzdata
COPY --from=build /out/grepalert-dashboard /usr/local/bin/
COPY examples/container/dashboard.yaml /etc/grepalert/dashboard.yaml
VOLUME /var/lib/grepalert-dashboard
EXPOSE 9400
HEALTHCHECK --interval=10s --timeout=3s CMD wget -qO- http://127.0.0.1:9400/healthz || exit 1
ENTRYPOINT ["grepalert-dashboard"]
CMD ["-config", "/etc/grepalert/dashboard.yaml"]

# Load-test only: an "application VM" that writes logs with loadgen and runs
# the agent next to it. See examples/loadtest.
FROM agent AS loadtest-vm
COPY --from=build /out/loadgen /usr/local/bin/
ENTRYPOINT ["sh", "-c", "mkdir -p /var/log/app && loadgen -out /var/log/app/app.log -rate ${LOG_RATE:-10MB} -rotate ${LOG_ROTATE:-1GB} -errors ${LOG_ERROR_PCT:-1} & exec grepalert-agent -config /etc/grepalert/agent.yaml"]
