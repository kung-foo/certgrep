package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"regexp"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/kung-foo/certgrep/tls_clone"
)

var DPDSSLServer = regexp.MustCompile(`^(\x16\x03[\x00\x01\x02\x03]..\x02...\x03[\x00\x01\x02\x03]).*`)
var DPDSSLClient = regexp.MustCompile(`^(\x16\x03[\x00\x01\x02\x03]..\x01...\x03[\x00\x01\x02\x03]).*`)

var flow_idx uint64 = 0

type FakeConn struct {
	net.Conn
	flow io.Reader
	idx  uint64
}

func (f *FakeConn) Read(b []byte) (n int, err error) {
	r, err := f.flow.Read(b)
	//log.Printf("F%02d   read  %d %d %v\n", f.idx, len(b), r, err)
	//log.Printf("%02x %02x %02x %02x\n", b[0], b[1], b[2], b[3])
	return r, err
}

func (f *FakeConn) Write(b []byte) (n int, err error) {
	//log.Printf("F%02d   write %d %d\n", f.idx, len(b), len(b))
	return len(b), nil
}

type ReaderFactory struct{}

func (t *ReaderFactory) New(netFlow gopacket.Flow, TCPflow gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go handleStream(&r, netFlow, TCPflow)
	return &r
}

func handleStream(r io.Reader, netflow gopacket.Flow, tcpflow gopacket.Flow) {
	defer func() {
		tcpreader.DiscardBytesToEOF(r)
	}()

	idx := atomic.AddUint64(&flow_idx, 1)

	data := bufio.NewReader(r)
	header, err := data.Peek(256)

	if err != nil {
		if err != io.EOF {
			log.Println(err)
		}
		return
	}

	//src, _ := tcpflow.Endpoints()
	if true {
		found_cert := false
		conn := tls_clone.Client(&FakeConn{flow: data, idx: idx}, &tls_clone.Config{InsecureSkipVerify: true})
		conn.Handshake()

		for _, cert := range conn.PeerCertificates() {
			if len(cert.DNSNames) > 0 {
				found_cert = true
				log.Printf("F%04d   %v %v\n", idx, netflow, tcpflow)
				log.Printf("F%04d   %v\n", idx, cert.Subject.CommonName)
				log.Printf("F%04d   %s\n\n\n    ", idx, cert.DNSNames)
			}
			//j, _ := json.Marshal(cert)
			//fmt.Println(string(j))
		}

		if found_cert && !DPDSSLServer.Match(header) {
			//log.Printf("F%04d HHMHMHMHMHMHM  %v %v\n", idx, netflow, tcpflow)
		}
	}
}
