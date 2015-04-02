VERSION := v0.0.1
BUILDSTRING := $(shell git log --pretty=format:'%h' -n 1)
VERSIONSTRING := certgrep version $(VERSION)+$(BUILDSTRING)

.PHONY: default gofmt all test clean

default: all

all: gofmt test build

certgrep: main.go reader.go
	godep go build -v -ldflags "-X main.VERSION \"$(VERSIONSTRING)\""

build: certgrep

gofmt:
	gofmt -w .

test: certgrep
	godep go test -cover -v ./...

clean:
	rm -f certgrep
