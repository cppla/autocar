GO ?= go
BINARY ?= bin/autocar
VERSION ?= dev
COMMIT ?= unknown
BUILD_DATE ?= unknown
LDFLAGS := -s -w \
	-X github.com/cppla/autocar/internal/version.Version=$(VERSION) \
	-X github.com/cppla/autocar/internal/version.Commit=$(COMMIT) \
	-X github.com/cppla/autocar/internal/version.Date=$(BUILD_DATE)

.PHONY: all check fmt fmt-check dependency-boundary-check mod-check notices notices-check vet test race build cross-build release docker integration-netem clean

all: check build

check: fmt-check dependency-boundary-check mod-check notices-check vet test

fmt:
	$(GO) fmt ./...

fmt-check:
	@set -eu; \
	go_bin="$$(command -v $(GO))" || { echo "Go tool not found: $(GO)" >&2; exit 1; }; \
	gofmt_bin="$$(dirname "$$go_bin")/gofmt"; \
	if [ ! -x "$$gofmt_bin" ]; then echo "gofmt not found next to $$go_bin" >&2; exit 1; fi; \
	unformatted="$$("$$gofmt_bin" -l .)" || exit $$?; \
	if [ -n "$$unformatted" ]; then printf '%s\n' "$$unformatted"; echo "Go files need formatting" >&2; exit 1; fi

dependency-boundary-check:
	./scripts/check-dependency-boundary.sh

mod-check:
	$(GO) mod tidy
	git diff --exit-code -- go.mod go.sum

notices:
	$(GO) run ./tools/notices

notices-check:
	$(GO) run ./tools/notices -check

vet:
	$(GO) vet ./...

test:
	$(GO) test -shuffle=on -count=1 ./...

race:
	CGO_ENABLED=1 $(GO) test -race -shuffle=on -count=1 ./...

build:
	mkdir -p $(dir $(BINARY))
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/autocar

cross-build: notices-check
	mkdir -p dist
	rm -f dist/autocar-linux-amd64 dist/autocar-linux-arm64 dist/autocar-darwin-arm64 dist/autocar-windows-amd64.exe
	rm -rf dist/.release-stage-autocar
	mkdir -p dist/.release-stage-autocar/autocar-linux-amd64
	mkdir -p dist/.release-stage-autocar/autocar-linux-arm64
	mkdir -p dist/.release-stage-autocar/autocar-darwin-arm64
	mkdir -p dist/.release-stage-autocar/autocar-windows-amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/.release-stage-autocar/autocar-linux-amd64/autocar ./cmd/autocar
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/.release-stage-autocar/autocar-linux-arm64/autocar ./cmd/autocar
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/.release-stage-autocar/autocar-darwin-arm64/autocar ./cmd/autocar
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/.release-stage-autocar/autocar-windows-amd64/autocar.exe ./cmd/autocar
	cp LICENSE THIRD_PARTY_NOTICES.md dist/.release-stage-autocar/autocar-linux-amd64/
	cp LICENSE THIRD_PARTY_NOTICES.md dist/.release-stage-autocar/autocar-linux-arm64/
	cp LICENSE THIRD_PARTY_NOTICES.md dist/.release-stage-autocar/autocar-darwin-arm64/
	cp LICENSE THIRD_PARTY_NOTICES.md dist/.release-stage-autocar/autocar-windows-amd64/
	tar -C dist/.release-stage-autocar/autocar-linux-amd64 -czf dist/autocar-linux-amd64.tar.gz autocar LICENSE THIRD_PARTY_NOTICES.md
	tar -C dist/.release-stage-autocar/autocar-linux-arm64 -czf dist/autocar-linux-arm64.tar.gz autocar LICENSE THIRD_PARTY_NOTICES.md
	tar -C dist/.release-stage-autocar/autocar-darwin-arm64 -czf dist/autocar-darwin-arm64.tar.gz autocar LICENSE THIRD_PARTY_NOTICES.md
	cd dist/.release-stage-autocar/autocar-windows-amd64 && zip -q -X ../../autocar-windows-amd64.zip autocar.exe LICENSE THIRD_PARTY_NOTICES.md
	rm -rf dist/.release-stage-autocar

release: cross-build

docker:
	docker build --build-arg VERSION="$(VERSION)" --build-arg COMMIT="$(COMMIT)" --build-arg BUILD_DATE="$(BUILD_DATE)" -t autocar:local .

integration-netem: build
	sudo ./scripts/netem-integration.sh ./$(BINARY)

clean:
	rm -rf bin dist artifacts
