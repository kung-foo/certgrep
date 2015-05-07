package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/docopt/docopt-go"
	. "github.com/smartystreets/goconvey/convey"
)

func TestMainArgs(t *testing.T) {
	Convey("main should have a short help flag", t, func() {
		args, _ := docopt.Parse(usage, []string{"-h"}, true, VERSION, true, false)
		So(args, ShouldBeEmpty)
	})

	Convey("main should have a long help flag", t, func() {
		args, _ := docopt.Parse(usage, []string{"--help"}, true, VERSION, true, false)
		So(args, ShouldBeEmpty)
	})

}

func TestEnd2End(t *testing.T) {
	Convey("write certificates to file", t, func() {
		output, err := ioutil.TempDir("", "goconvey")
		So(err, ShouldBeNil)
		defer os.Remove(output)

		argv := []string{
			"--pcap", "testdata/sess_smtps.pcapng",
			"--output", output,
			"--format", "json",
			"--format", "der",
			"--format", "yaml",
			"--no-color",
		}

		mainEx(argv)

		matches, err := filepath.Glob(output + "/*")
		So(err, ShouldBeNil)
		So(len(matches), ShouldEqual, 1)
		captureDir := matches[0]

		for _, format := range []string{"der", "json", "yaml"} {
			Convey(fmt.Sprintf("%s should be correct", format), func() {
				matches, err := filepath.Glob(captureDir + "/*." + format)
				So(err, ShouldBeNil)
				So(len(matches), ShouldEqual, 3)

				for _, f := range matches {
					h, err := os.Open(f)
					So(err, ShouldBeNil)
					s, err := h.Stat()
					So(err, ShouldBeNil)
					So(s.Size(), ShouldBeGreaterThan, 0)
				}
			})
		}
	})
}

/*
func TestMainFullIntegration(t *testing.T) {
	Convey("when running from main()", t, func() {
		Convey("it should panic when", func() {
			Convey("a non-existient PCAP is specified", func() {
				argv := []string{"--pcap", "testdata/NOT_HERE.pcapng"}
				So(func() { mainEx(argv) }, ShouldPanic)
			})

			Convey("a non-existient interface is specified", func() {
				argv := []string{"--interface", "nope"}
				So(func() { mainEx(argv) }, ShouldPanic)
			})
		})

		Convey("full pcap test 1", func() {
			argv := []string{"--pcap", "testdata/sess_test_1.pcapng"}
			mainEx(argv)
		})
	})
}
*/
