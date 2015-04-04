package main

import (
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
