FROM golang:1.7
MAINTAINER me@jonathan.camp

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -yq \
    libpcap-dev

RUN mkdir -p /go/src/github.com/kung-foo/certgrep
WORKDIR /go/src/github.com/kung-foo/certgrep

RUN go get -v golang.org/x/tools/cmd/cover

RUN echo 'tput setaf 2\necho run "make" to build certgrep\ntput sgr0' >> /etc/bash.bashrc
