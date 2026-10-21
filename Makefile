VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
LDFLAGS := -s -w -X github.com/fadhaw/grepalert/internal/version.Version=$(VERSION)

.PHONY: build ui ui-dev test dist clean

build: ui
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

# The dashboard's web UI (React, in ui/). The build lands in
# internal/dashboard/web/dist and is embedded into the dashboard binary.
ui: ui/node_modules
	cd ui && npm run build

ui/node_modules: ui/package.json ui/package-lock.json
	cd ui && npm ci
	touch ui/node_modules

# Hot-reloading UI on http://localhost:5173, using the API of a dashboard
# running on :9400 (GREPALERT_DASHBOARD=http://host:port to change).
ui-dev: ui/node_modules
	cd ui && npm run dev

test:
	go vet ./...
	go test ./...

# Release archives for every platform, plus checksums, into dist/ (what the
# release workflow publishes).
dist:
	VERSION=$(VERSION) scripts/release.sh

clean:
	rm -rf bin dist internal/dashboard/web/dist
