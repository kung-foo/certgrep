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
$ sudo ./certgrep-linux-amd64 -i wlan0 --format der --format json -o /tmp/capture/
2015/04/19 18:46:07 writing to /tmp/capture/2015-04-19T16_46_07Z
2015/04/19 18:46:09 server:192.30.252.129 port:443 client:192.168.5.136 commonname:"github.com" serial:15953718796281471505685363726901697671 fingerprint:58875244d86012b0fbd5f6c06ef16efca20e158d58e96e6f76ceda6660b59bc2
2015/04/19 18:46:09 server:192.30.252.129 port:443 client:192.168.5.136 commonname:"DigiCert SHA2 Extended Validation Server CA" serial:16582437038678467094619379592629788035 fingerprint:403e062a2653059113285baf80a0d4ae422c848c9f78fad01fc94bc5b87fef1a
^C
2015/04/19 18:46:12 capture time: 2 seconds
2015/04/19 18:46:12 capture size: 28802 bytes
2015/04/19 18:46:12 average capture rate: 102.287 Kbit/s
2015/04/19 18:46:12 pps: 10
```

A request to `https://github.com` generates four certificates in the output folder `/tmp/capture/2015-04-19T16_43_35Z`.

```
$ ls -Al /tmp/capture/2015-04-19T16_46_07Z
total 24K
-rw-r--r-- 1 root root 1,5K april 19 18:46 00000003-00-5887524-192.30.252.129-443-192.168.5.136-github.com.der
-rw-r--r-- 1 root root 6,8K april 19 18:46 00000003-00-5887524-192.30.252.129-443-192.168.5.136-github.com.json
-rw-r--r-- 1 root root 1,2K april 19 18:46 00000003-01-403e062-192.30.252.129-443-192.168.5.136-DigiCertSHA2ExtendedValidationServerCA.der
-rw-r--r-- 1 root root 5,2K april 19 18:46 00000003-01-403e062-192.30.252.129-443-192.168.5.136-DigiCertSHA2ExtendedValidationServerCA.json
```

The syntax for the filename is:

`TCPFLOWINDEX-CERTINDEX-SERVERIP-SERVERPORT-CLIENTIP-COMMONNAME.FORMAT`
