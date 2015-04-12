Build Instructions
==================

### Common Requirements
* Go (https://golang.org/)
* godep (https://github.com/tools/godep)
* libpcap

Ubuntu
------

For a [Docker](https://www.docker.com/) based build environment please go [here](#docker).

* Install Go (>= 1.3) (see: https://golang.org/doc/install)
* Install dependencies
```
$ sudo apt-get install libpcap-dev build-essential git
$ go get -v github.com/tools/godep
```
* Download source
```
$ git clone https://github.com/kung-foo/certgrep $GOPATH/src/github.com/kung-foo/certgrep
```
* Build
```
$ make build
```

### Testing on Ubuntu

```
./certgrep -p testdata/sess_smtps.pcapng
2015/04/11 18:28:31 flowid:2 server:68.114.188.72 port:587 client:10.74.5.100 commonname:"mobile.charter.net" serial:73397715042707340270384354846404777809
2015/04/11 18:28:31 flowid:2 server:68.114.188.72 port:587 client:10.74.5.100 commonname:"Thawte SSL CA" serial:102844720425577770632960998383784151532
2015/04/11 18:28:31 flowid:2 server:68.114.188.72 port:587 client:10.74.5.100 commonname:"thawte Primary Root CA" serial:68316673031993696956121215362381360273
```

Windows
-------
* Install 64-bit Go release
* Install 64-bit gcc toolchain (http://win-builds.org/doku.php)
* WinPcap Developer's Pack (https://www.winpcap.org/devel.htm)
    * Unzip into `c:\WpdPack` (see: [gopacket/pcap/pcap.go ](https://github.com/google/gopacket/blob/master/pcap/pcap.go#L15))
* Install dependencies
```
go get -v github.com/tools/godep
```
* Build binary
```
mingw32-make # if using mingw toolchain
# OR
godep go build -v
```

### Testing on Windows

```
certgrep.exe -p testdata\sess_smtps.pcapng
2015/04/11 18:28:31 flowid:2 server:68.114.188.72 port:587 client:10.74.5.100 commonname:"mobile.charter.net" serial:73397715042707340270384354846404777809
2015/04/11 18:28:31 flowid:2 server:68.114.188.72 port:587 client:10.74.5.100 commonname:"Thawte SSL CA" serial:102844720425577770632960998383784151532
2015/04/11 18:28:31 flowid:2 server:68.114.188.72 port:587 client:10.74.5.100 commonname:"thawte Primary Root CA" serial:68316673031993696956121215362381360273
```

Docker
------
> Note: **libpcap** is still required to run **certgrep**

```
$ make docker-build-shell
docker build -t jonathancamp/certgrep .
...
Successfully built f20ea8b8781d
...
run make to build certgrep
root@7052acf56fe8:/go/src/github.com/kung-foo/certgrep# make
...
Built ./certgrep-linux-amd64
root@7052acf56fe8:/go/src/github.com/kung-foo/certgrep# exit
$ ./certgrep-linux-amd64 --version
certgrep version v0.0.1+6604387
```
