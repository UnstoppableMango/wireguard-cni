DOCKER ?= docker
GINKGO ?= ginkgo
GO     ?= go

GOVERSION ?= $(shell go env GOVERSION | sed 's/go//')
GO_IMAGE  ?= golang:$(GOVERSION)
GOPATH    ?= $(shell go env GOPATH)

GO_SRC := $(shell find . -name '*.go')

build: bin/wireguard-cni
tidy: go.sum gomod2nix.toml
docker container ctr: bin/image.tar.gz

# Run unit tests only (no root required)
test:
	$(GINKGO) run -r --label-filter="!integration"

load: bin/stream-image.sh
	${CURDIR}/$ | ${DOCKER} load

format fmt:
	nix fmt

go.sum: go.mod ${GO_SRC}
	$(GO) mod tidy

gomod2nix.toml: go.sum
	$(GOMOD2NIX) generate

bin/wireguard-cni: ${GO_SRC}
	$(GO) build -o $@ .

bin/stream-image.sh: ${GO_SRC}
	nix build .#ctr --out-link $@

bin/image.tar.gz: bin/stream-image.sh
	${CURDIR}/$< >$@

# Run all tests inside a privileged Docker container (no sudo required)
test-container:
	$(DOCKER) run --rm \
	  --privileged \
	  -v "$(CURDIR):/src" \
	  -v "$(GOPATH)/pkg/mod:/go/pkg/mod" \
	  -w /src \
	  $(GO_IMAGE) \
	  $(GO) test -v ./...
