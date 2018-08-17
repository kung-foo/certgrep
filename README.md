# certgrep

**certgrep** is a cross-platform command line tool that extracts TLS/SSL certificates from either a network interface or a local PCAP file. The certificates are saved in either JSON, DER and/or PEM format.

Utilizes [google/gopacket] (https://github.com/google/gopacket)

Usage
-----

```
Usage:
    certgrep [options] [-v ...] [--format=<format> ...] (-p=<pcap> | -i=<interface>)
    certgrep [options] [-v ...] -l | --list
    certgrep -h | --help | --version

Options:
    -h --help               Show this screen.
    --version               Show version.
    -l --list               List available interfaces
    -p --pcap=<pcap>        PCAP file to parse
    -i --interface=<iface>  Network interface to listen on
    -o --output=<output>    Resource output directory [default: certs]
    --log-to-stdout         Write certificate log to stdout
    -f --format=<format>    Certificate output format (json|der|pem) [default: pem]
    -b --bpf=<bpf>          Capture filter (BPF) [default: tcp]
    --no-color              Disabled colored output
    -v                      Enable verbose logging (-vv for very verbose)
    --profile
    --assembly-memuse-log
    --assembly-debug-log
    --dump-metrics
    --dump-packets
```

Example
-------

```
$ sudo ./dist/certgrep-linux-amd64 -i wlp58s0 --format pem --format json --log-to-stdout
2018-08-17T10:11:14.340+0200	INFO	certgrep	certgrep/extractor.go:86	setting output dir to: certs/2018-08-17T08_11_14Z
2018-08-17T08:11:15Z flowidx:9 flowhash:f1a0fb33d0ef19ba client:192.168.5.14 server:192.30.253.113 port:443 cert:0 cn:"github.com" fingerprint:ca06f56b258b7a0d4f2b05470939478651151984 serial:13324412563135569597699362973539517727
2018-08-17T08:11:15Z flowidx:9 flowhash:f1a0fb33d0ef19ba client:192.168.5.14 server:192.30.253.113 port:443 cert:1 cn:"DigiCert SHA2 Extended Validation Server CA" fingerprint:7e2f3a4f8fe8fa8a5730aeca029696637e986f3f serial:16582437038678467094619379592629788035
^C
2018-08-17T10:11:17.749+0200	INFO	certgrep	certgrep/extractor.go:168	capture time: 3 seconds
2018-08-17T10:11:17.749+0200	INFO	certgrep	certgrep/extractor.go:169	capture size: 22508 bytes
2018-08-17T10:11:17.749+0200	INFO	certgrep	certgrep/extractor.go:173	average capture rate: 64.256 Kbit/s
2018-08-17T10:11:17.749+0200	INFO	certgrep	certgrep/extractor.go:179	pps: 18
```

A request to `https://github.com` generates two certificates in the output folder `./certs/2018-08-17T08_11_14Z`.

```
$ tree certs/2018-08-17T08_11_14Z
certs/2018-08-17T08_11_14Z
├── 7e2f3a4f8fe8fa8a5730aeca029696637e986f3f
│   ├── cert.json
│   └── cert.pem
└── ca06f56b258b7a0d4f2b05470939478651151984
    ├── cert.json
    └── cert.pem
```
