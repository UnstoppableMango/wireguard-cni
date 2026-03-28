PODMAN    ?= podman
GINKGO    ?= ginkgo
GO        ?= go
GOMOD2NIX ?= gomod2nix
KIND      ?= kind
KUBECTL   ?= kubectl
SKOPEO    ?= skopeo

VERSION    ?= v0.0.1-alpha
IMAGE      ?= localhost/wireguard-cni
GOVERSION  ?= $(shell $(GO) env GOVERSION | sed 's/go//')
GOMODCACHE ?= $(shell $(GO) env GOMODCACHE)

GO_SRC := $(shell find . -name '*.go')

build: bin/wireguard-cni
tidy: go.sum gomod2nix.toml
docker container ctr: bin/image.tar

cover: coverprofile.out
	$(GO) tool cover -func=$<

load: bin/stream-image.sh bin/stream-tools.sh
	${CURDIR}/bin/stream-image.sh | $(PODMAN) load
	${CURDIR}/bin/stream-tools.sh | $(PODMAN) load

format fmt:
	nix fmt

check:
	nix flake check

.PHONY: test test-unit test-k8s
test:
	@mkdir -p ${GOMODCACHE}
	$(PODMAN) run --rm \
		--privileged \
		-v "${CURDIR}:/src" \
		-v "${GOMODCACHE}:/go/pkg/mod" \
		-w /src \
		golang:$(GOVERSION) \
		go test -v ./...

test-unit:
	$(GINKGO) run -r --label-filter="!e2e"

test-k8s:
	$(GINKGO) run -r --label-filter="k8s" .

go.sum: go.mod ${GO_SRC}
	$(GO) mod tidy

gomod2nix.toml: go.sum
	$(GOMOD2NIX) generate

bin/wireguard-cni: | result/bin/wireguard-cni
	mkdir -p ${@D} && ln -sf ${CURDIR}/$| ${CURDIR}/$@

bin/stream-image.sh: ${GO_SRC} nix/container.nix
	nix build .#ctr --out-link $@ --no-update-lock-file
bin/stream-tools.sh: nix/tools.nix
	nix build .#ctrtools --out-link $@ --no-update-lock-file

bin/image.tar: bin/stream-image.sh
	${CURDIR}/$< | $(SKOPEO) copy \
		docker-archive:/dev/stdin \
		docker-archive:${CURDIR}/$@ \
		${TAGS:%=--additional-tag %}

bin/image-oci: bin/stream-image.sh
	${CURDIR}/$< | $(SKOPEO) copy \
		docker-archive:/dev/stdin oci:${CURDIR}/$@

coverprofile.out: ${GO_SRC}
	$(GINKGO) run -r --cover --label-filter="!e2e"

result/bin/wireguard-cni: ${GO_SRC}
	nix build .#wireguard-cni --no-update-lock-file

CLUSTER    ?= wireguard-cni
KUBECONFIG := ${CURDIR}/.kube/config

.PHONY: kind kind-cluster kind-load kind-deploy kind-delete
kind: kind-cluster kind-deploy

kind-cluster: hack/kind-config.yaml
	$(KIND) get clusters | grep -q "^${CLUSTER}$$" || \
		$(KIND) create cluster --name ${CLUSTER} --config $< --kubeconfig ${KUBECONFIG}

kind-load: bin/stream-image.sh bin/stream-tools.sh
	$(CURDIR)/bin/stream-image.sh | $(KIND) load image-archive /dev/stdin --name ${CLUSTER}
	$(CURDIR)/bin/stream-tools.sh | $(KIND) load image-archive /dev/stdin --name ${CLUSTER}

kind-deploy: kind-load
	$(KUBECTL) --kubeconfig ${KUBECONFIG} apply -k hack/

kind-delete:
	$(KIND) get clusters | grep -q "^${CLUSTER}$$" && \
		$(KIND) delete cluster --name ${CLUSTER} --kubeconfig ${KUBECONFIG} || true
