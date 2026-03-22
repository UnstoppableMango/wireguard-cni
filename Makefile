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

test:
	$(GINKGO) run -r --label-filter="!integration"

cover: coverprofile.out
	$(GO) tool cover -func=coverprofile.out

load: bin/stream-image.sh
	${CURDIR}/$< | ${DOCKER} load

format fmt:
	nix fmt

check:
	nix flake check

# Run all tests inside a privileged Docker container (no sudo required)
test-privileged:
	$(DOCKER) run --rm \
	  --privileged \
	  -v "$(CURDIR):/src" \
	  -v "$(GOPATH)/pkg/mod:/go/pkg/mod" \
	  -w /src \
	  $(GO_IMAGE) \
	  go test -v ./...

go.sum: go.mod ${GO_SRC}
	$(GO) mod tidy

gomod2nix.toml: go.sum
	$(GOMOD2NIX) generate

bin/wireguard-cni: | result/bin/wireguard-cni
	mkdir -p ${@D} && ln -sf ${CURDIR}/$| ${CURDIR}/$@

bin/stream-image.sh: ${GO_SRC}
	nix build .#ctr --out-link $@

bin/image.tar.gz: bin/stream-image.sh
	${CURDIR}/$< >$@

coverprofile.out: ${GO_SRC}
	$(GINKGO) run -r --cover --label-filter="!integration"

result/bin/wireguard-cni: ${GO_SRC}
	nix build .#wireguard-cni
