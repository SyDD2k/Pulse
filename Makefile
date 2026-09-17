.PHONY: all bpf go test clean docker run

all: bpf go

bpf:
	$(MAKE) -C bpf

go:
	go build -o bin/ebpfca ./cmd/ebpfca

test:
	go test ./...

clean:
	$(MAKE) -C bpf clean
	rm -rf bin/

docker:
	docker compose build

run:
	sudo ./bin/ebpfca -config configs/ebpfca.yml
