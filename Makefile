BINARY := obrien
GOFLAGS ?=

# A pure-Go build is statically linked, so the binary runs on any Linux of
# the same architecture regardless of its libc version.
export CGO_ENABLED := 0

# kettlingar-go is built from the local submodule via the replace directive
# in go.mod, so edits under submodules/kettlingar-go are picked up directly.
KETTLINGAR := submodules/kettlingar-go

.PHONY: all build vet fmt test submodules clean

all: build

build: $(KETTLINGAR)/go.mod
	go build $(GOFLAGS) -trimpath -ldflags "-s -w" -o $(BINARY) .

# Fetch the submodule if this is a fresh clone.
$(KETTLINGAR)/go.mod:
	git submodule update --init $(KETTLINGAR)

submodules:
	git submodule update --init

vet:
	go vet ./...

test:
	go test ./...
	cd $(KETTLINGAR) && go test ./...

# Format our own sources only; leave the submodule alone.
fmt:
	gofmt -w *.go proxy rules monitor

clean:
	rm -f $(BINARY)
