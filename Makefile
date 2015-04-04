VERSION := v0.0.1
BUILDSTRING := $(shell git log --pretty=format:'%h' -n 1)
VERSIONSTRING := certgrep version $(VERSION)+$(BUILDSTRING)

.PHONY: default gofmt all test clean goconvey

default: all

all: gofmt test build

certgrep: main.go reader.go tls_clone/hackage.go
	godep go build -v -ldflags "-X main.VERSION \"$(VERSIONSTRING)\""

build: certgrep

gofmt:
	gofmt -w .

goconvey:
	#goconvey -gobin='godepgo'
	goconvey

test:
	godep go test -cover -v ./...

clean:
	rm -f certgrep
