VERSION = v$(strip $(shell cat VERSION))

BUILDSTRING := git:[$(shell git log --pretty=format:'%h' -n 1)] go:[$(shell go version | sed 's/go version //')]
VERSIONSTRING := certgrep $(VERSION) $(BUILDSTRING)
DIMAGE := kung-foo/certgrep

ifndef GOARCH
	GOARCH := $(shell go env GOARCH)
endif

ifndef GOOS
	GOOS := $(shell go env GOOS)
endif

OUTPUT := ./dist/certgrep-$(GOOS)-$(GOARCH)

ifeq ($(GOOS), windows)
	OUTPUT := $(OUTPUT).exe
endif

.PHONY: default all clean

default: build

$(OUTPUT): *.go cmd/certgrep/*.go tls_clone/*.go
	mkdir -p dist/
	go build -v -o $(OUTPUT) -ldflags '-X "main.VERSION=$(VERSIONSTRING)"' cmd/certgrep/main.go
ifdef CALLING_UID
ifdef CALLING_GID
	@echo Reseting owner to $(CALLING_UID):$(CALLING_GID)
	chown $(CALLING_UID):$(CALLING_GID) $(OUTPUT)
endif
endif
	@echo
	@echo Built $(OUTPUT)

build: $(OUTPUT)

clean:
	rm -f $(OUTPUT)
