package main

import (
	"os"
	"os/signal"

	"github.com/davecgh/go-spew/spew"
	docopt "github.com/docopt/docopt-go"
	"github.com/google/gopacket/pcap"
	. "github.com/kung-foo/certgrep"
	isatty "github.com/mattn/go-isatty"
	"github.com/pkg/errors"
	"github.com/pkg/profile"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	snaplen = 65536
)

// VERSION is set by the makefile
var VERSION = "0.0.0-notset"

var slogger *zap.SugaredLogger

var usage = `
Usage:
    certgrep [options] [-v ...] [--format=<format> ...] (-p=<pcap> | -i=<interface>)
    certgrep [options] [-v ...] -l | --list
    certgrep -h | --help | --version

Options:
    -h --help               Show this screen.
    --version               Show version.
    -l --list               List available interfaces
    -p --pcap=<pcap>        PCAP file to parse
    -i --interface=<iface>  Network interface to listen on
    -o --output=<output>    Resource output directory [default: certs]
    --log-to-stdout         Write certificate log to stdout
    -f --format=<format>    Certificate output format (json|der|pem) [default: pem]
    -b --bpf=<bpf>          Capture filter (BPF) [default: tcp]
    --no-color              Disabled colored output
    -v                      Enable verbose logging (-vv for very verbose)
    --profile
    --assembly-memuse-log
    --assembly-debug-log
    --dump-metrics
    --dump-packets
`

// for --assembly-memuse-log and --assembly-debug-log see:
// https://github.com/google/gopacket/blob/v1.1.14/tcpassembly/assembly.go#L31-L32

func main() {
	mainEx(os.Args[1:])
}

func mainEx(argv []string) {
	var err error
	args, _ := docopt.Parse(usage, argv, true, VERSION, true)

	if args["--profile"].(bool) {
		profiler := profile.Start(profile.CPUProfile, profile.ProfilePath("profiling"))
		defer func() {
			profiler.Stop()
		}()
	}

	config := zap.NewDevelopmentConfig()
	if !args["--no-color"].(bool) && ttySupportsColor() {
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	if args["-v"].(int) > 0 {
		config.Level.SetLevel(zap.DebugLevel)
	} else {
		config.Level.SetLevel(zap.InfoLevel)
	}

	logger, err := config.Build()
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	slogger = logger.Sugar()

	if args["--list"].(bool) {
		onErrorExit(PrintDeviceTable(os.Stdout, slogger))
		return
	}

	var handle *pcap.Handle

	if args["--pcap"] != nil {
		handle, err = pcap.OpenOffline(args["--pcap"].(string))
		onErrorExit(err)
	}

	if args["--interface"] != nil {
		handle, err = pcap.OpenLive(args["--interface"].(string), snaplen, true, pcap.BlockForever)
		if err != nil {
			slogger.Info("Run --list to view available capture interfaces.")
			onErrorExit(err)
		}
	}

	if err = handle.SetBPFFilter(args["--bpf"].(string)); err != nil {
		onErrorExit(errors.Wrap(err, "error setting BPF filter"))
	}

	var extractor *Extractor

	options := make([]Option, 0)

	if args["--format"] != nil {
		for _, format := range args["--format"].([]string) {
			options = append(options, EnableOutputFormat(format, true))
		}
	}

	options = append(options, Logger(slogger))
	options = append(options, OutputDir(args["--output"].(string)))
	options = append(options, LogToStdout(args["--log-to-stdout"].(bool)))

	extractor, err = NewExtractor(handle, options...)
	onErrorExit(err)

	onInterruptSignal(func() {
		os.Stdout.WriteString("\n")
		extractor.Close()
	})

	extractor.Run()

	stats, err := handle.Stats()
	if err == nil {
		spew.Dump(*stats)
	}
	handle.Close()
}

func onErrorExit(err error) {
	if err != nil {
		slogger.Fatal(err)
	}
}

func onInterruptSignal(fn func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		<-sig
		fn()
	}()
}

func ttySupportsColor() bool {
	fd := os.Stdout.Fd()
	return isatty.IsTerminal(fd) || isatty.IsCygwinTerminal(fd)
}
