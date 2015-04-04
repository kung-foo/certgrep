package main

import (
	"bufio"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"regexp"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	tls_clone "github.com/kung-foo/certgrep/tls_clone"
)

var NO_SSL_HANDSHAKE_FOUND = errors.New("No SSL handshake found")

var log_line = "flowid:%d server:%s port:%s client:%s commonname:\"%s\" serial:%s"

var peek_sz = 16
var server_hs_regex = regexp.MustCompile(`^\x16\x03[\x00\x01\x02\x03].*`)

var flow_idx uint64 = 0

type fakeConn struct {
	net.Conn
	flow io.Reader
	idx  uint64
}

func (f *fakeConn) Read(b []byte) (int, error) {
	return f.flow.Read(b)
}

func (f *fakeConn) Write(b []byte) (int, error) {
	return len(b), nil
}

type ReaderFactory struct{}

func (t *ReaderFactory) New(netflow gopacket.Flow, tcpflow gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	h := NewStreamHandler(&r, netflow, tcpflow)

	go func() {
		// TODO: this should go someplace else...
		defer r.Close()
		err := h.Run()
		if err != nil {
			//log.Println(err)
		}
	}()

	return &r
}

type streamHandler struct {
	r       io.Reader
	netflow *gopacket.Flow
	tcpflow *gopacket.Flow
	idx     uint64
}

func NewStreamHandler(r io.Reader, netflow gopacket.Flow, tcpflow gopacket.Flow) *streamHandler {
	return &streamHandler{
		r:       r,
		netflow: &netflow,
		tcpflow: &tcpflow,
		idx:     atomic.AddUint64(&flow_idx, 1),
	}
}

func (s *streamHandler) key() string {
	src, dst := s.netflow.Endpoints()
	return fmt.Sprintf("%s-%s-%s", src, s.tcpflow.Src(), dst)
}

func (s *streamHandler) Run() error {
	defer func() {
		tcpreader.DiscardBytesToEOF(s.r)
	}()

	data := bufio.NewReader(s.r)
	t, err := data.Peek(peek_sz)

	if err != nil {
		if err != io.EOF {
			log.Println(err)
			return err
		}
		return nil
	}

	header := make([]byte, peek_sz)
	copy(header, t)

	if s.isSslHandshake(header) {
		certs, err := s.extractCertificates(&fakeConn{flow: data, idx: s.idx})
		if err != nil {
			return err
		}

		if len(certs) > 0 {
			src, dst := s.netflow.Endpoints()
			for _, cert := range certs {
				line := fmt.Sprintf(log_line, s.idx, src.String(), s.tcpflow.Src(), dst.String(), cert.Subject.CommonName, cert.SerialNumber)
				log.Println(line)
			}
		}

		/*
			if len(certs) > 0 {
				bmap_mtx.Lock()
				for i, b := range header {
					bmap[i][b] += 1
				}
				bmap_mtx.Unlock()
			}
		*/
	} else {
		return NO_SSL_HANDSHAKE_FOUND
	}

	return nil
}

func (s *streamHandler) extractCertificates(conn net.Conn) ([]*x509.Certificate, error) {
	client := tls_clone.Client(conn, &tls_clone.Config{InsecureSkipVerify: true})
	client.Handshake()
	// TODO: log various errors. some are interesting.
	certs := client.PeerCertificates()
	return certs, nil
}

func (s *streamHandler) isSslHandshake(data []byte) bool {
	return server_hs_regex.Match(data)
}
