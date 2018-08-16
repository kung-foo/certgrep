package certgrep

import (
	"bufio"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sync/atomic"

	"go.uber.org/zap"

	"encoding/hex"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	tls_clone "github.com/kung-foo/certgrep/tls_clone"
)

var (
	// ErrNoSSLHandshakeFound is used to indicate no handshake found
	ErrNoTLSHandshakeFound = errors.New("No TLS handshake found")

	// IgnoredTLSErrors is a map of errors that do not keep the certificates
	// from being extracted
	IgnoredTLSErrors = map[string]bool{
		"tls: received unexpected handshake message of type *tls.clientHelloMsg when waiting for *tls.serverHelloMsg": true,
		"crypto/rsa: verification error":                                                                              true,
		"local error: bad record MAC":                                                                                 true,
		"ECDSA verification failure":                                                                                  true,
		"tls: server selected unsupported curve":                                                                      true,
		"tls: unknown hash function used by peer":                                                                     true,
		"missing ServerKeyExchange message":                                                                           true,
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

type readerFactory struct {
	logger *zap.SugaredLogger
	output *output
}

func (t *readerFactory) New(netflow gopacket.Flow, tcpflow gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	h := newStreamHandler(&r, netflow, tcpflow, t.output, t.logger.Named("stream"))

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
	output     *output
	logger     *zap.SugaredLogger
}

func newStreamHandler(r io.Reader, netflow gopacket.Flow, tcpflow gopacket.Flow, output *output, logger *zap.SugaredLogger) *streamHandler {
	return &streamHandler{
		r:       r,
		netflow: &netflow,
		tcpflow: &tcpflow,
		idx:     atomic.AddUint64(&atomicFlowIdx, 1),
		output:  output,
		logger:  logger,
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
	//if Config.verbose {
	return fmt.Sprintf("flowidx:%d flowhash:%s client:%s server:%s port:%s",
		s.idx, s.hash(), dst.String(), src.String(), s.tcpflow.Src())
	//}
	//return fmt.Sprintf("server:%s port:%s client:%s", src.String(), s.tcpflow.Src(), dst.String())
}

func (s *streamHandler) Run() error {
	defer func() {
		n := tcpreader.DiscardBytesToEOF(s.r)
		//if s.foundCerts && Config.veryVerbose {
		if s.foundCerts {
			s.logger.Debugf("%s DiscardBytesToEOF:%d", s.logPrefix(), n)
		}
	}()

	data := bufio.NewReader(s.r)
	t, err := data.Peek(peekSz)

	if err != nil {
		if err != io.EOF {
			s.logger.Error(err)
			return err
		}
		return nil
	}

	header := make([]byte, peekSz)
	copy(header, t)

	//if Config.veryVerbose {
	s.logger.Debugf("%s header:%s", s.logPrefix(), hex.EncodeToString(header))
	//}

	if s.isTLSHandshake(header) {
		certs, err := s.extractCertificates(&fakeConn{flow: data, idx: s.idx})
		if err != nil {
			return err
		}

		s.foundCerts = len(certs) > 0

		if s.foundCerts {
			s.output.PersistCertificate(certs, s.logPrefix())
		}

		// TODO(jca): handshake but no certs??

		return nil
	}
	return ErrNoTLSHandshakeFound
}

func (s *streamHandler) extractCertificates(conn net.Conn) ([]*x509.Certificate, error) {
	client := tls_clone.Client(conn, &tls_clone.Config{InsecureSkipVerify: true})
	err := client.Handshake()
	if !IgnoredTLSErrors[err.Error()] {
		//if s.netflow != nil && Config.verbose {
		if s.netflow != nil {
			if len(client.PeerCertificates()) == 0 {
				s.logger.Debugf("%s %s %v", redError("ERROR"), s.logPrefix(), err)
			} else {
				// possibly ignoreable error
				s.logger.Debugf("%s %s %v", redError("ADD TO IGNORE"), s.logPrefix(), err)
			}
		}
	}
	// TODO: log various errors. some are interesting.
	certs := client.PeerCertificates()
	return certs, nil
}

func (s *streamHandler) isTLSHandshake(data []byte) bool {
	return serverHSRegex.Match(data)
}
