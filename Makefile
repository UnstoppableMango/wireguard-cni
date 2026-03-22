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

.PHONY: build tidy test test-unit
