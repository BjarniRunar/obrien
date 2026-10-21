BINARY := police

.PHONY: all build vet fmt clean

all: build

build:
	go build -trimpath -ldflags "-s -w" -o $(BINARY) .

vet:
	go vet ./...

fmt:
	gofmt -w .

clean:
	rm -f $(BINARY)
