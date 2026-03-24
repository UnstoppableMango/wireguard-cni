DOCKER    ?= docker
GINKGO    ?= ginkgo
GO        ?= go
GOMOD2NIX ?= gomod2nix
SKOPEO    ?= skopeo

VERSION   ?= v0.0.1-alpha
IMAGE     ?= wireguard-cni:${VERSION}
REPO	  ?= localhost/${IMAGE}
GOVERSION ?= $(shell $(GO) env GOVERSION | sed 's/go//')
GO_IMAGE  ?= golang:$(GOVERSION)
GOPATH    ?= $(shell $(GO) env GOPATH)

GO_SRC := $(shell find . -name '*.go')

build: bin/wireguard-cni
tidy: go.sum gomod2nix.toml
docker container ctr: bin/image.tar.gz

cover: coverprofile.out
	$(GO) tool cover -func=$<

load: bin/stream-image.sh
	${CURDIR}/$< | ${DOCKER} load

format fmt:
	nix fmt

check:
	nix flake check

.PHONY: test test-unit
test:
	$(DOCKER) run --rm \
	--privileged \
	-v "$(CURDIR):/src" \
	-v "$(GOPATH)/pkg/mod:/go/pkg/mod" \
	-w /src \
	$(GO_IMAGE) \
	go test -v ./...

test-unit:
	$(GINKGO) run -r --label-filter="!e2e"

push: ./bin/stream-image.sh
	${CURDIR}/$< | $(SKOPEO) copy \
	docker-archive:/dev/stdin docker://${REPO} \
	${TAGS:%=--additional-tag %}

go.sum: go.mod ${GO_SRC}
	$(GO) mod tidy

gomod2nix.toml: go.sum
	$(GOMOD2NIX) generate

bin/wireguard-cni: | result/bin/wireguard-cni
	mkdir -p ${@D} && ln -sf ${CURDIR}/$| ${CURDIR}/$@

bin/stream-image.sh: ${GO_SRC}
	nix build .#ctr --out-link $@ --no-update-lock-file

bin/image.tar.gz: bin/stream-image.sh
	${CURDIR}/$< >$@

bin/image-oci: bin/stream-image.sh
	${CURDIR}/$< | $(SKOPEO) copy \
	docker-archive:/dev/stdin oci:./$@

coverprofile.out: ${GO_SRC}
	$(GINKGO) run -r --cover --label-filter="!e2e"

result/bin/wireguard-cni: ${GO_SRC}
	nix build .#wireguard-cni --no-update-lock-file
