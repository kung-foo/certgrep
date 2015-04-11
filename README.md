# certgrep

[![Circle CI](https://circleci.com/gh/kung-foo/certgrep/tree/develop.svg?style=svg)](https://circleci.com/gh/kung-foo/certgrep/tree/develop) [![Coverage Status](https://coveralls.io/repos/kung-foo/certgrep/badge.svg?branch=develop)](https://coveralls.io/r/kung-foo/certgrep?branch=develop)

**certgrep** is a cross-platform command line tool that extracts SSL certificates from either a network interface or a local PCAP file. The certificates are saved in either JSON and/or DER format.

```
Usage:
    certgrep [options] [--format=<format> ...] (-p=<pcap> | -i=<interface>)
    certgrep -h | --help | --version

Options:
    -h --help               Show this screen.
    --version               Show version.
    -p --pcap=<pcap>        PCAP file to parse
    -i --interface=<iface>  Network interface to listen on
    -o --output=<output>    Output directory
    -f --format=<format>    Output format (json|der) [default: json]
    -v                      Enable verbose logging.
    --assembly-memuse-log
    --assembly-debug-log
    --dump-metrics
```

Example:

```
$ sudo ./certgrep --format json -o /tmp/capture -i wlan0
2015/04/08 21:34:34 writing to /tmp/capture/2015-04-08T19_34_34Z
2015/04/08 21:34:45 flowid:9 server:69.192.72.154 port:443 client:192.168.5.136 commonname:"www.microsoft.com" serial:82365655871428336739211871484630851433
2015/04/08 21:34:45 flowid:9 server:69.192.72.154 port:443 client:192.168.5.136 commonname:"Symantec Class 3 EV SSL CA - G3" serial:168652503989349361584430187274382793396
2015/04/08 21:34:45 flowid:9 server:69.192.72.154 port:443 client:192.168.5.136 commonname:"VeriSign Class 3 Public Primary Certification Authority - G5" serial:49248466687453522052688216172288342269
```
