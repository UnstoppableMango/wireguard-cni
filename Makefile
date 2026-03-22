GOVERSION ?= $(shell go env GOVERSION | sed 's/go//')
GO_IMAGE  ?= golang:$(GOVERSION)
GOPATH    ?= $(shell go env GOPATH)

build: bin/wireguard-cni
tidy: go.sum

go.sum: go.mod
	go mod tidy

bin/wireguard-cni: main.go config.go wireguard.go network.go
	go build -o $@ .

# Run unit tests only (no root required)
test-unit:
	go test --ginkgo.focus='Config|parseAddress|parseWGKey' -v ./...

# Run all tests including integration tests (requires root / CAP_NET_ADMIN)
test:
	sudo go test -v ./...

# Run all tests inside a privileged Docker container (no sudo required)
test-container:
	docker run --rm \
	  --privileged \
	  -v "$(CURDIR):/src" \
	  -v "$(GOPATH)/pkg/mod:/go/pkg/mod" \
	  -w /src \
	  $(GO_IMAGE) \
	  go test -v ./...

.PHONY: build tidy test test-unit test-container
