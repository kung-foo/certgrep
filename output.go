package certgrep

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"time"
)

type output struct {
	persist     chan *ctx
	done        chan struct{}
	certLogFile io.WriteCloser
	options     outputOptions
}

type outputOptions struct {
	der  bool
	json bool
	pem  bool
	dir  string
}

type ctx struct {
	certs   []*x509.Certificate
	logLine string
	/*
		src      gopacket.Endpoint
		dst      gopacket.Endpoint
		flowId   uint64
		flowHash string
	*/
}

func newOutput(logfile string, options outputOptions) (*output, error) {
	var (
		err error
		clf *os.File
	)
	if logLine == "-" {
		clf = os.Stdout
	} else {
		clf, err = os.Create(path.Join(options.dir, logfile))
		if err != nil {
			return nil, err
		}
	}
	o := &output{
		persist:     make(chan *ctx),
		done:        make(chan struct{}),
		certLogFile: clf,
		options:     options,
	}
	go o.run()
	return o, nil
}

func (o *output) PersistCertificate(certs []*x509.Certificate,
	logLine string) {
	o.persist <- &ctx{
		certs:   certs,
		logLine: logLine,
	}
}

func (o *output) run() {
	for ctx := range o.persist {
		for i, cert := range ctx.certs {
			h := sha1.New()
			h.Write(cert.Raw)
			digest := hex.EncodeToString(h.Sum(nil))

			path := filepath.Join(o.options.dir, digest)

			// TODO: break if cert already written

			if err := os.MkdirAll(path, defaultDirPerm); err != nil {
				log.Fatal(err)
			}

			// log.Printf("%d %s %s", i, digest, cert.Subject.CommonName)
			// log.Print(cert.Verify(x509.VerifyOptions{}))

			//if !cert.IsCA {
			//log.Print(cert.CheckSignatureFrom(cert))
			//}

			if o.options.der {
				ioutil.WriteFile(filepath.Join(path, "cert.der"), cert.Raw, 0644)
			}

			if o.options.pem {
				func() {
					block := pem.Block{
						Type:  "CERTIFICATE",
						Bytes: cert.Raw,
					}

					out, err := os.Create(filepath.Join(path, "cert.pem"))
					if err != nil {
						log.Fatal(err)
					}
					defer out.Close()

					err = pem.Encode(out, &block)
					if err != nil {
						log.Fatal(err)
					}
				}()
			}

			// Note: cert.Verify requires cert.Raw
			cert.Raw = nil
			cert.RawIssuer = nil
			cert.RawSubject = nil
			cert.RawSubjectPublicKeyInfo = nil
			cert.RawTBSCertificate = nil

			if o.options.json {
				raw, err := json.MarshalIndent(cert, "", "  ")
				if err != nil {
					log.Fatal(err)
				}
				ioutil.WriteFile(filepath.Join(path, "cert.json"), raw, 0644)
			}

			// TODO(jca): proper escaping
			fmt.Fprintf(o.certLogFile,
				"%s %s cert:%d cn:\"%s\" fingerprint:%s serial:%s\n",
				time.Now().UTC().Format(time.RFC3339), ctx.logLine,
				i, cert.Subject.CommonName, digest, cert.SerialNumber.String())
		}
	}
	close(o.done)
}

func (o *output) WaitUntilDone() {
	close(o.persist)
	<-o.done
	o.certLogFile.Close()
}
