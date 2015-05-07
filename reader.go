package main

import (
	"bufio"
	"crypto/sha1"
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

	"gopkg.in/yaml.v2"

	"encoding/hex"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	tls_clone "github.com/kung-foo/certgrep/tls_clone"
)

var (
	// ErrNoSSLHandshakeFound is used to indicate no handshake found
	ErrNoSSLHandshakeFound = errors.New("No SSL handshake found")

	// IgnoredTLSErrors is a map of errors that do not keep the certificates
	// from being extracted
	IgnoredTLSErrors = map[string]bool{
		"tls: received unexpected handshake message of type *tls.clientHelloMsg when waiting for *tls.serverHelloMsg": true,
		"crypto/rsa: verification error":                                                                              true,
		"local error: bad record MAC":                                                                                 true,
		"ECDSA verification failure":                                                                                  true,
		"tls: server selected unsupported curve":                                                                      true,
	}
)

const (
	peekSz = 16
)

var (
	// SSL handshake regex
	serverHSRegex = regexp.MustCompile(`^\x16\x03[\x00\x01\x02\x03].*`)
	// common name chars allowed in file name
	allowedCNCchars = regexp.MustCompile(`([^a-zA-Z0-9_\.\-])`)
	logLine         = "%s commonname:\"%s\" serial:%s fingerprint:%s"
)

func cleanupName(name string) string {
	n := allowedCNCchars.ReplaceAllLiteralString(name, "")
	if len(n) > 256 {
		n = n[0:256]
	}
	return n
}

var atomicFlowIdx uint64

type fakeConn struct {
	net.Conn
	flow      io.Reader
	idx       uint64
	bytesRead int
}

func (f *fakeConn) Read(b []byte) (n int, err error) {
	n, err = f.flow.Read(b)
	f.bytesRead += n
	return
}

func (f *fakeConn) Write(b []byte) (int, error) {
	return len(b), nil
}

type readerFactory struct{}

func (t *readerFactory) New(netflow gopacket.Flow, tcpflow gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	h := newStreamHandler(&r, netflow, tcpflow)

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
	r          io.Reader
	netflow    *gopacket.Flow
	tcpflow    *gopacket.Flow
	idx        uint64
	foundCerts bool
}

func newStreamHandler(r io.Reader, netflow gopacket.Flow, tcpflow gopacket.Flow) *streamHandler {
	return &streamHandler{
		r:       r,
		netflow: &netflow,
		tcpflow: &tcpflow,
		idx:     atomic.AddUint64(&atomicFlowIdx, 1),
	}
}

func (s *streamHandler) hash() string {
	return fmt.Sprintf("%016x", s.tcpflow.FastHash())
}

func (s *streamHandler) key() string {
	src, dst := s.netflow.Endpoints()
	return fmt.Sprintf("%s-%s-%s", src, s.tcpflow.Src(), dst)
}

func (s *streamHandler) logPrefix() string {
	src, dst := s.netflow.Endpoints()
	if Config.verbose {
		return fmt.Sprintf("flowidx:%d flowhash:%s server:%s port:%s client:%s", s.idx, s.hash(), src.String(), s.tcpflow.Src(), dst.String())
	}
	return fmt.Sprintf("server:%s port:%s client:%s", src.String(), s.tcpflow.Src(), dst.String())
}

func (s *streamHandler) Run() error {
	defer func() {
		n := tcpreader.DiscardBytesToEOF(s.r)
		if s.foundCerts && Config.veryVerbose {
			log.Printf("%s DiscardBytesToEOF:%d", s.logPrefix(), n)
		}
	}()

	data := bufio.NewReader(s.r)
	t, err := data.Peek(peekSz)

	if err != nil {
		if err != io.EOF {
			log.Println(err)
			return err
		}
		return nil
	}

	header := make([]byte, peekSz)
	copy(header, t)

	if Config.veryVerbose {
		log.Printf("%s header:%s", s.logPrefix(), hex.EncodeToString(header))
	}

	if s.isSslHandshake(header) {
		certs, err := s.extractCertificates(&fakeConn{flow: data, idx: s.idx})
		if err != nil {
			return err
		}

		s.foundCerts = len(certs) > 0

		if s.foundCerts {
			src, dst := s.netflow.Endpoints()
			for i, cert := range certs {

				h := sha1.New()
				h.Write(cert.Raw)
				digest := hex.EncodeToString(h.Sum(nil))

				if Config.output != "" {
					commonname := cleanupName(cert.Subject.CommonName)
					path := filepath.Join(
						Config.output,
						fmt.Sprintf("%08d-%02d-%s-%s-%s-%s-%s", s.idx, i, digest[0:7], src.String(), s.tcpflow.Src(), dst.String(), commonname))

					if Config.der {
						ioutil.WriteFile(fmt.Sprintf("%s.der", path), cert.Raw, 0644)
					}

					// TODO: convert crypto/x509 into something were I control the serialization

					// null out some fields that aren't needed in the json/yaml
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

					if Config.yaml {
						raw, err := yaml.Marshal(cert)
						if err != nil {
							log.Fatal(err)
						}
						ioutil.WriteFile(fmt.Sprintf("%s.yaml", path), raw, 0644)
					}
				}

				line := fmt.Sprintf(logLine, s.logPrefix(), cert.Subject.CommonName, cert.SerialNumber, digest)
				log.Println(line)
			}
		}
	} else {
		return ErrNoSSLHandshakeFound
	}

	return nil
}

func (s *streamHandler) extractCertificates(conn net.Conn) ([]*x509.Certificate, error) {
	client := tls_clone.Client(conn, &tls_clone.Config{InsecureSkipVerify: true})
	err := client.Handshake()
	if !IgnoredTLSErrors[err.Error()] {
		if s.netflow != nil && Config.verbose {
			if len(client.PeerCertificates()) == 0 {
				log.Printf("%s %s %v", redError("ERROR"), s.logPrefix(), err)
			} else {
				// possibly ignoreable error
				log.Printf("%s %s %v", redError("ADD TO IGNORE"), s.logPrefix(), err)
			}
		}
	}
	// TODO: log various errors. some are interesting.
	certs := client.PeerCertificates()
	return certs, nil
}

func (s *streamHandler) isSslHandshake(data []byte) bool {
	return serverHSRegex.Match(data)
}
