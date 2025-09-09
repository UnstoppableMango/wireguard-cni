build: bin/wireguard-cni
tidy: go.sum

go.sum: main.go
	go mod tidy

bin/wireguard-cni: main.go
	go build -o $@ $<
