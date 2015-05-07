VERSION := v0.0.2
BUILDSTRING := $(shell git log --pretty=format:'%h' -n 1)
VERSIONSTRING := certgrep version $(VERSION)+$(BUILDSTRING)
DIMAGE := kung-foo/certgrep

ifndef GOARCH
	GOARCH := $(shell go env GOARCH)
endif

ifndef GOOS
	GOOS := $(shell go env GOOS)
endif

OUTPUT := certgrep-$(GOOS)-$(GOARCH)

ifeq ($(GOOS), windows)
	OUTPUT := $(OUTPUT).exe
endif

.PHONY: default gofmt all test clean goconvey docker-build

default: build

$(OUTPUT): main.go reader.go tls_clone/*.go
	godep go build -v -o $(OUTPUT) -ldflags "-X main.VERSION \"$(VERSIONSTRING)\"" .
ifdef CALLING_UID
ifdef CALLING_GID
	@echo Reseting owner to $(CALLING_UID):$(CALLING_GID)
	chown $(CALLING_UID):$(CALLING_GID) $(OUTPUT)
endif
endif
	@echo
	@echo Built ./$(OUTPUT)

build: $(OUTPUT)

gofmt:
	gofmt -w .

update-godeps:
	rm -rf Godeps
	godep save

test:
	godep go test -cover -v ./...

clean:
	rm -f $(OUTPUT)

docker-build:
	docker build -t $(DIMAGE) .

docker-build-shell: docker-build
	docker run \
		--rm -it \
		-v $(PWD):/go/src/github.com/kung-foo/certgrep \
		-e CALLING_UID=$(shell id -u) \
		-e CALLING_GID=$(shell id -g) \
		-e HISTFILE="" \
		$(DIMAGE) \
		bash -i
