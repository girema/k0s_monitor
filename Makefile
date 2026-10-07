BINARY  := k0s-monitor
PKG     := k0s_monitor
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

.PHONY: build test lint e2e usability dist image clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/k0s-monitor

test:
	go test -race ./...

lint:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	go vet ./...

# Needs Docker with privileged containers; see test/e2e/run.sh. The web
# part also needs sudo and systemd, and installs a k0s-monitor service.
e2e: build
	KEEP=1 test/e2e/run.sh
	test/e2e/web.sh

# The usability round (test/usability/README.md): its three clusters as
# fake clusters, with a fresh database each time, on https://127.0.0.1:8443.
usability:
	CGO_ENABLED=0 go build -tags demo -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY)-demo ./cmd/k0s-monitor
	bin/$(BINARY)-demo serve --demo 'test/usability/clusters/*.yaml' --data-dir "$$(mktemp -d)"

dist:
	@mkdir -p dist
	for arch in amd64 arm64; do \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' \
			-o dist/$(BINARY)-linux-$$arch ./cmd/k0s-monitor || exit 1; \
	done
	cd dist && sha256sum $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 > SHA256SUMS

# The container image for this machine's architecture (see Dockerfile).
image:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) -t $(BINARY):$(VERSION) .

clean:
	rm -rf bin dist
