BINARY := obrien
GOFLAGS ?=

# A pure-Go build is statically linked, so the binary runs on any Linux of
# the same architecture regardless of its libc version.
export CGO_ENABLED := 0

# kettlingar-go and coraza are built from the local submodules via the replace
# directives in go.mod, so edits under submodules/ are picked up directly.
KETTLINGAR := submodules/kettlingar-go
CORAZA := submodules/coraza

.PHONY: all build vet fmt test submodules clean

all: build

build: $(KETTLINGAR)/go.mod $(CORAZA)/go.mod
	go build $(GOFLAGS) -trimpath -ldflags "-s -w" -o $(BINARY) .

# Fetch the submodules if this is a fresh clone.
$(KETTLINGAR)/go.mod:
	git submodule update --init $(KETTLINGAR)

$(CORAZA)/go.mod:
	git submodule update --init $(CORAZA)

submodules:
	git submodule update --init

vet:
	go vet ./...

test:
	go test ./...
	cd $(KETTLINGAR) && go test ./...
	cd $(CORAZA) && go test ./...

# Format our own sources only; leave the submodule alone.
fmt:
	gofmt -w *.go proxy rules monitor

clean:
	rm -f $(BINARY)
