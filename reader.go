package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"path/filepath"
	"regexp"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	tls_clone "github.com/kung-foo/certgrep/tls_clone"
)

var NO_SSL_HANDSHAKE_FOUND = errors.New("No SSL handshake found")

const (
	peek_sz = 16
)

var (
	server_hs_regex  = regexp.MustCompile(`^\x16\x03[\x00\x01\x02\x03].*`)
	allowed_cn_chars = regexp.MustCompile(`([^a-zA-Z0-9_\.\-])`)
	log_line         = "flowid:%d server:%s port:%s client:%s commonname:\"%s\" serial:%s"
)

func cleanupName(name string) string {
	n := allowed_cn_chars.ReplaceAllLiteralString(name, "")
	if len(n) > 256 {
		n = n[0:256]
	}
	return n
}

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
			for i, cert := range certs {
				line := fmt.Sprintf(log_line, s.idx, src.String(), s.tcpflow.Src(), dst.String(), cert.Subject.CommonName, cert.SerialNumber)
				log.Println(line)
				if Config.output != "" {
					commonname := cleanupName(cert.Subject.CommonName)
					path := filepath.Join(
						Config.output,
						fmt.Sprintf("%08d-%02d-%s-%s-%s", s.idx, i, src.String(), s.tcpflow.Src(), commonname))

					if Config.der {
						ioutil.WriteFile(fmt.Sprintf("%s.der", path), cert.Raw, 0644)
					}

					// null out some fields that aren't needed in the json
					cert.Raw = nil
					cert.RawIssuer = nil
					cert.RawSubject = nil
					cert.RawSubjectPublicKeyInfo = nil
					cert.RawTBSCertificate = nil

					if Config.json {
						raw, err := json.MarshalIndent(cert, "", "  ")
						if err != nil {
							log.Fatal(err)
						}
						ioutil.WriteFile(fmt.Sprintf("%s.json", path), raw, 0644)
					}
				}
			}
		}
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
