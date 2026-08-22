GO ?= go
BINARY ?= bin/autocar
VERSION ?= dev
COMMIT ?= unknown
BUILD_DATE ?= unknown
LDFLAGS := -s -w \
	-X github.com/cppla/autocar/internal/version.Version=$(VERSION) \
	-X github.com/cppla/autocar/internal/version.Commit=$(COMMIT) \
	-X github.com/cppla/autocar/internal/version.Date=$(BUILD_DATE)

.PHONY: all check fmt fmt-check mod-check vet test race build cross-build docker integration-netem clean

all: check build

check: fmt-check mod-check vet test

fmt:
	$(GO) fmt ./...

fmt-check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "Go files need formatting" >&2; exit 1; }

mod-check:
	$(GO) mod tidy
	git diff --exit-code -- go.mod go.sum

vet:
	$(GO) vet ./...

test:
	$(GO) test -shuffle=on -count=1 ./...

race:
	CGO_ENABLED=1 $(GO) test -race -shuffle=on -count=1 ./...

build:
	mkdir -p $(dir $(BINARY))
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/autocar

cross-build:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/autocar-linux-amd64 ./cmd/autocar
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/autocar-linux-arm64 ./cmd/autocar
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/autocar-darwin-arm64 ./cmd/autocar
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/autocar-windows-amd64.exe ./cmd/autocar

docker:
	docker build --build-arg VERSION="$(VERSION)" --build-arg COMMIT="$(COMMIT)" --build-arg BUILD_DATE="$(BUILD_DATE)" -t autocar:local .

integration-netem: build
	sudo ./scripts/netem-integration.sh ./$(BINARY)

clean:
	rm -rf bin dist artifacts
