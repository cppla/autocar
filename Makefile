GO ?= go
BINARY ?= bin/autocar
VERSION ?= dev
COMMIT ?= unknown
BUILD_DATE ?= unknown
LDFLAGS := -s -w \
	-X github.com/cppla/autocar/internal/version.Version=$(VERSION) \
	-X github.com/cppla/autocar/internal/version.Commit=$(COMMIT) \
	-X github.com/cppla/autocar/internal/version.Date=$(BUILD_DATE)

.PHONY: all check fmt fmt-check dependency-boundary-check mod-check notices notices-check vet test race build cross-build release release-recipe-check release-evidence-check docker integration-docker integration-netem stealth-tools-check stealth-active-smoke stealth-active-release stealth-campaign-calibration stealth-campaign-full stealth-campaign-docker-smoke stealth-passive clean

STEALTH_PREREGISTRATION ?= testdata/stealth/preregistration.json
STEALTH_EXPECTED_REMOTE_HOST ?=

all: check build

check: fmt-check dependency-boundary-check mod-check notices-check vet test release-recipe-check

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
	$(GO) mod tidy -diff

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

release: release-evidence-check
	@test "$(VERSION)" != dev || { echo "set VERSION to the release version" >&2; exit 2; }
	@test "$(BUILD_DATE)" != unknown || { echo "set BUILD_DATE to the release timestamp" >&2; exit 2; }
	@set -eu; commit="$$(git rev-parse --verify HEAD)"; tree="$$(git rev-parse "HEAD^{tree}")"; \
	test -z "$$(git status --porcelain=v1 --untracked-files=all)" || { echo "release checkout became dirty" >&2; exit 1; }; \
	$(MAKE) cross-build VERSION="$(VERSION)" COMMIT="$$commit" BUILD_DATE="$(BUILD_DATE)"; \
	test "$$(git rev-parse --verify HEAD)" = "$$commit" && test "$$(git rev-parse "HEAD^{tree}")" = "$$tree" && \
	test -z "$$(git status --porcelain=v1 --untracked-files=all)" || { echo "release source changed while archives were built" >&2; exit 1; }

release-recipe-check:
	python3 scripts/test_make_release.py

release-evidence-check: stealth-tools-check
	@test -n "$(STEALTH_LOCAL_ACTIVE)" || { echo "set STEALTH_LOCAL_ACTIVE=/path/to/local/manifest.json" >&2; exit 2; }
	@test -n "$(STEALTH_REMOTE_ACTIVE)" || { echo "set STEALTH_REMOTE_ACTIVE=/path/to/remote/manifest.json" >&2; exit 2; }
	@test -n "$(STEALTH_EXPECTED_REMOTE_HOST)" || { echo "set STEALTH_EXPECTED_REMOTE_HOST=host:port" >&2; exit 2; }
	@test -n "$(STEALTH_EXTRACTION)" || { echo "set STEALTH_EXTRACTION=/path/to/extraction.json" >&2; exit 2; }
	@test -n "$(STEALTH_SCORES)" || { echo "set STEALTH_SCORES=/path/to/scores.json" >&2; exit 2; }
	@test -n "$(STEALTH_CAMPAIGN)" || { echo "set STEALTH_CAMPAIGN=/path/to/campaign.json" >&2; exit 2; }
	@test -n "$(STEALTH_CAPTURE_MANIFEST)" || { echo "set STEALTH_CAPTURE_MANIFEST=/path/to/manifest.csv" >&2; exit 2; }
	@test -n "$(STEALTH_FEATURES)" || { echo "set STEALTH_FEATURES=/path/to/features.csv" >&2; exit 2; }
	@test -n "$(STEALTH_AUTOCAR_BINARY)" || { echo "set STEALTH_AUTOCAR_BINARY=/path/to/autocar" >&2; exit 2; }
	@test -n "$(STEALTH_AUTOCAR_CONFIG)" || { echo "set STEALTH_AUTOCAR_CONFIG=/path/to/effective-autocar-config" >&2; exit 2; }
	@test -n "$(STEALTH_HYSTERIA_BINARY)" || { echo "set STEALTH_HYSTERIA_BINARY=/path/to/hysteria" >&2; exit 2; }
	@test -n "$(STEALTH_HYSTERIA_CONFIG)" || { echo "set STEALTH_HYSTERIA_CONFIG=/path/to/effective-hysteria-config" >&2; exit 2; }
	@commit="$$(git rev-parse --verify HEAD)"; \
	python3 scripts/stealth-release-check.py \
		--local-active "$(STEALTH_LOCAL_ACTIVE)" \
		--remote-active "$(STEALTH_REMOTE_ACTIVE)" \
		--expected-remote-host "$(STEALTH_EXPECTED_REMOTE_HOST)" \
		--extraction "$(STEALTH_EXTRACTION)" \
		--scores "$(STEALTH_SCORES)" \
		--campaign "$(STEALTH_CAMPAIGN)" \
		--capture-manifest "$(STEALTH_CAPTURE_MANIFEST)" \
		--features "$(STEALTH_FEATURES)" \
		--autocar-binary "$(STEALTH_AUTOCAR_BINARY)" \
		--autocar-config "$(STEALTH_AUTOCAR_CONFIG)" \
		--hysteria-binary "$(STEALTH_HYSTERIA_BINARY)" \
		--hysteria-config "$(STEALTH_HYSTERIA_CONFIG)" \
		--preregistration "$(STEALTH_PREREGISTRATION)" \
		--expected-commit "$$commit" --repo-root .

docker:
	docker build --build-arg VERSION="$(VERSION)" --build-arg COMMIT="$(COMMIT)" --build-arg BUILD_DATE="$(BUILD_DATE)" -t autocar:local .

integration-docker:
	./scripts/docker-integration.sh

integration-netem: build
	sudo ./scripts/netem-integration.sh ./$(BINARY)

stealth-tools-check: release-recipe-check
	$(GO) test -race ./scripts/stealth-probe
	GOPROXY=off $(GO) test ./scripts/stealth-pilot
	sh -n scripts/stealth-active.sh scripts/stealth-hysteria.sh scripts/stealth-passive.sh scripts/stealth-campaign-smoke.sh scripts/stealth-pilot.sh scripts/stealth-offline-container.sh scripts/stealth-full-lab.sh scripts/stealth-full-offline.sh
	sh -n scripts/check-stealth-hysteria-update-disabled.sh
	./scripts/check-stealth-hysteria-update-disabled.sh
	python3 scripts/stealth-pilot-config.py self-test
	python3 scripts/stealth-features.py --self-test
	python3 scripts/stealth-classify.py --self-test
	python3 scripts/stealth-release-check.py --self-test
	python3 scripts/stealth-campaign.py --self-test
	python3 scripts/stealth-full-config.py self-test
	./scripts/stealth-full-offline.sh self-test
	python3 -m unittest scripts/stealth-browser/test_run_cover.py

stealth-active-smoke: stealth-tools-check
	STEALTH_ITERATIONS=3 STEALTH_RELEASE_GATE=0 ./scripts/stealth-active.sh

stealth-active-release: stealth-tools-check
	STEALTH_ITERATIONS=100 STEALTH_RELEASE_GATE=1 STEALTH_RUN_ROLE=local-docker ./scripts/stealth-active.sh

stealth-campaign-calibration: stealth-tools-check
	@test -n "$(STEALTH_CAPTURE_CONFIG)" || { echo "set STEALTH_CAPTURE_CONFIG=/path/to/campaign-driver.json" >&2; exit 2; }
	@test -n "$(STEALTH_CAPTURE_OUTPUT)" || { echo "set STEALTH_CAPTURE_OUTPUT=/new/output-directory" >&2; exit 2; }
	python3 scripts/stealth-campaign.py --mode calibration \
		--config "$(STEALTH_CAPTURE_CONFIG)" --output "$(STEALTH_CAPTURE_OUTPUT)"

stealth-campaign-full: stealth-tools-check
	@test -n "$(STEALTH_CAPTURE_CONFIG)" || { echo "set STEALTH_CAPTURE_CONFIG=/path/to/campaign-driver.json" >&2; exit 2; }
	@test -n "$(STEALTH_CAPTURE_OUTPUT)" || { echo "set STEALTH_CAPTURE_OUTPUT=/new/output-directory" >&2; exit 2; }
	python3 scripts/stealth-campaign.py --mode full \
		--config "$(STEALTH_CAPTURE_CONFIG)" --output "$(STEALTH_CAPTURE_OUTPUT)"

stealth-campaign-docker-smoke: stealth-tools-check
	./scripts/stealth-campaign-smoke.sh

stealth-passive: stealth-tools-check
	@test -n "$(STEALTH_MANIFEST)" || { echo "set STEALTH_MANIFEST=/path/to/manifest.csv" >&2; exit 2; }
	@test -n "$(STEALTH_OUTPUT)" || { echo "set STEALTH_OUTPUT=/path/to/output-directory" >&2; exit 2; }
	./scripts/stealth-passive.sh "$(STEALTH_MANIFEST)" "$(STEALTH_OUTPUT)"

clean:
	rm -rf bin dist artifacts
