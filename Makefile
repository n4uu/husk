VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: build test vet lint fixture clean install

build:
	go build -ldflags "$(LDFLAGS)" -o bin/husk ./cmd/husk

test:
	go test ./...

vet:
	go vet ./...

lint: vet
	@command -v golangci-lint >/dev/null && golangci-lint run || \
		echo "golangci-lint not installed, ran go vet only"

# Writes a synthetic, non-malicious sample config to try `husk parse` on.
fixture: build
	./bin/husk fixture -out sample.bin

clean:
	rm -rf bin sample.bin

install: build
	install -Dm755 bin/husk /usr/local/bin/husk
