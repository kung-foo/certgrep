package tls

import "crypto/x509"

func (c *Conn) PeerCertificates() []*x509.Certificate {
	return c.peerCertificates
}
