package main

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/gopacket"
	"github.com/kung-foo/certgrep/testdata"
	. "github.com/smartystreets/goconvey/convey"
)

func TestSslHandshake(t *testing.T) {
	Convey("Raw bytes should be a server->client handshake", t, func() {
		sh := &streamHandler{}
		So(sh.isSslHandshake(testdata.Stream1), ShouldBeTrue)
	})
}

func TestStreamIndexing(t *testing.T) {
	Convey("multiple stream handlers should have consecutive indicies", t, func() {
		r1 := bytes.NewReader(testdata.Stream1)
		sh1 := NewStreamHandler(r1, gopacket.Flow{}, gopacket.Flow{})
		sh1.Run()

		r2 := bytes.NewReader(testdata.Stream1)
		sh2 := NewStreamHandler(r2, gopacket.Flow{}, gopacket.Flow{})
		sh2.Run()

		So(sh2.idx, ShouldEqual, sh1.idx+1)
	})
}

func TestFakeConn(t *testing.T) {
	Convey("the fake connection object", t, func() {
		b := []byte{0x00, 0x01, 0x02, 0x03}

		Convey("should write four bytes", func() {
			c := &fakeConn{
				flow: bytes.NewReader(b),
				idx:  0,
			}
			n, err := c.Write([]byte{0xff, 0xff, 0xff, 0xff})
			So(n, ShouldEqual, 4)
			So(err, ShouldBeNil)
		})

		Convey("should write a lot bytes", func() {
			c := &fakeConn{
				flow: bytes.NewReader(b),
				idx:  0,
			}
			b := make([]byte, 1024*1024)
			n, err := c.Write(b)
			So(n, ShouldEqual, len(b))
			So(err, ShouldBeNil)
		})

		Convey("a valid read", func() {
			c := &fakeConn{
				flow: bytes.NewReader(b),
				idx:  0,
			}
			b := make([]byte, 4)
			n, err := c.Read(b)
			So(n, ShouldEqual, 4)
			So(err, ShouldBeNil)
			So(b, ShouldResemble, []byte{0x00, 0x01, 0x02, 0x03})
		})

		Convey("an invalid read", func() {
			var n int
			var err error

			c := &fakeConn{
				flow: bytes.NewReader(b),
				idx:  0,
			}
			b := make([]byte, 4)
			n, err = c.Read(b)
			So(n, ShouldEqual, 4)
			So(err, ShouldBeNil)

			n, err = c.Read(b)
			So(n, ShouldEqual, 0)
			So(err, ShouldEqual, io.EOF)
		})
	})
}

func TestEmptyReader(t *testing.T) {
	Convey("an empty io reader should...", t, func() {
		Convey("not panic", func() {
			sh := &streamHandler{r: bytes.NewReader([]byte{})}
			So(func() { sh.Run() }, ShouldNotPanic)
		})

		Convey("return EOF", func() {
			Convey("well, now we return nil", func() {
				sh := &streamHandler{r: bytes.NewReader([]byte{})}
				err := sh.Run()
				So(err, ShouldEqual, nil)
			})
		})
	})
}

func TestCertificates(t *testing.T) {
	Convey("the certificate extractor should be able to", t, func() {
		Convey("get certs from a byte array", func() {
			sh := &streamHandler{}
			data := bytes.NewReader(testdata.Stream1)
			certs, err := sh.extractCertificates(&fakeConn{flow: data})

			So(err, ShouldBeNil)
			So(len(certs), ShouldEqual, 1)

			So(certs[0].SerialNumber.String(), ShouldEqual, "12217829665962172")
			So(certs[0].Subject.CommonName, ShouldEqual, "www.vxdb.io")
			So(certs[0].DNSNames, ShouldResemble, []string{"www.vxdb.io", "vxdb.io"})
		})
	})
}
