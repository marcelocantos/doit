VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

MAKEFLAGS += -j$(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

.PHONY: all build test vet clean install smoke bullseye

all: build

build: bin/doit

bin/doit:
	go build $(LDFLAGS) -o bin/doit ./cmd/doit

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin/

install: build
	cp bin/doit $(GOPATH)/bin/doit

smoke: build
	bin/doit --version

# Standing invariants hook read by /cv (bullseye_convergence).
# Exit 0 means all invariants green; non-zero surfaces the first
# violation to the convergence recommendation.
bullseye:
	@set -e; \
	go vet ./... && echo "✓ vet"; \
	go test ./... >/dev/null && echo "✓ tests"; \
	go build ./... && echo "✓ build"; \
	if [ -z "$$(git status --porcelain)" ]; then \
		echo "✓ clean"; \
	else \
		echo "✗ dirty tree"; git status --short; exit 1; \
	fi
