VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

MAKEFLAGS += -j$(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

.PHONY: all build test vet clean install smoke

all: build

build: internal/cli/help_agent.md
	go build $(LDFLAGS) -o bin/doit ./cmd/doit

internal/cli/help_agent.md: agents-guide.md
	cp agents-guide.md internal/cli/help_agent.md

test: internal/cli/help_agent.md
	go test ./...

vet: internal/cli/help_agent.md
	go vet ./...

clean:
	rm -rf bin/ internal/cli/help_agent.md

install: build
	cp bin/doit $(GOPATH)/bin/doit

smoke: build
	bin/doit --version
	bin/doit --list
	echo "hello world" | bin/doit --pipe cat ¦ wc -w
