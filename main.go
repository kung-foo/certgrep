package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/mgutz/ansi"
	"github.com/rcrowley/go-metrics"
)

type config struct {
	output  string
	json    bool
	der     bool
	yaml    bool
	verbose bool
}

var Config = &config{}

var bmap = make([][]int, 256)
var bmap_mtx = sync.RWMutex{}

var (
	packet_count  = metrics.NewMeter()
	gr_gauge      = metrics.NewGauge()
	flushed_count = metrics.NewMeter()
)

const (
	snaplen = 65536
)

var DEBUG_METRICS = false

var VERSION string
var usage = `
Usage:
    certgrep [options] [--format=<format> ...] (-p=<pcap> | -i=<interface>)
    certgrep -h | --help | --version

Options:
    -h --help               Show this screen.
    --version               Show version.
    -p --pcap=<pcap>        PCAP file to parse
    -i --interface=<iface>  Network interface to listen on
    -o --output=<output>    Output directory
    -f --format=<format>    Output format (json|yaml|der) [default: json]
    -b --bpf=<bpf>          Capture filter [default: tcp]
    --no-color              Disabled colored output
    -v --verbose            Enable verbose logging
    --assembly-memuse-log
    --assembly-debug-log
    --dump-metrics
`

func main() {
	mainEx(os.Args[1:])
}

func mainEx(argv []string) {
	args, _ := docopt.Parse(usage, argv, true, VERSION, true)

	if args["--no-color"].(bool) {
		ansi.DisableColors(true)
	}

	// little hack here to allow gopacket's debug flags to be set from the cmd line
	flag_args := make([]string, 0)

	if args["--assembly-memuse-log"].(bool) {
		flag_args = append(flag_args, "-assembly_memuse_log")
	}
	if args["--assembly-debug-log"].(bool) {
		flag_args = append(flag_args, "-assembly_debug_log")
	}

	flag.CommandLine.Parse(flag_args)

	Config.verbose = args["--verbose"].(bool)

	if Config.verbose {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	}

	var handle *pcap.Handle
	var err error

	if args["--pcap"] != nil {
		handle, err = pcap.OpenOffline(args["--pcap"].(string))
		if err != nil {
			log.Fatal(err)
		}
	}

	if args["--interface"] != nil {
		handle, err = pcap.OpenLive(args["--interface"].(string), snaplen, true, pcap.BlockForever)
		if err != nil {
			log.Fatal(err)
		}
	}

	if err := handle.SetBPFFilter(args["--bpf"].(string)); err != nil {
		log.Fatal("error setting BPF filter: ", err)
	}

	if args["--output"] != nil {
		path := filepath.Join(args["--output"].(string), strings.Replace(time.Now().UTC().Format(time.RFC3339), ":", "_", -1))
		if err := os.MkdirAll(path, 0777); err != nil {
			log.Fatal(err)
		}
		log.Printf("writing to %s", path)
		Config.output = path
	}

	if args["--format"] != nil {
		for _, format := range args["--format"].([]string) {
			if format == "json" {
				Config.json = true
			}
			if format == "der" {
				Config.der = true
			}
			if format == "yaml" {
				Config.yaml = true
			}
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	pool := tcpassembly.NewStreamPool(&ReaderFactory{})
	assembler := tcpassembly.NewAssembler(pool)

	//assembler.MaxBufferedPagesPerConnection = 8
	//assembler.MaxBufferedPagesTotal = 0

	packets := packetSource.Packets()
	ticker := time.Tick(time.Second * 2)

	DEBUG_METRICS = args["--dump-metrics"].(bool)

	if DEBUG_METRICS {
		metrics.Register("packet_count", packet_count)
		packet_count.Mark(0)

		gr_gauge := metrics.NewGauge()
		metrics.Register("gr_gauge", gr_gauge)
		gr_gauge.Update(int64(runtime.NumGoroutine()))

		metrics.Register("flushed_count", flushed_count)
		flushed_count.Mark(0)

		go metrics.Log(metrics.DefaultRegistry, time.Second*5, log.New(os.Stderr, "metrics: ", log.Lmicroseconds))
	}

	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				goto done
			}
			if err := packet.ErrorLayer(); err != nil {
				//fmt.Println(err)
			} else {
				if netLayer := packet.NetworkLayer(); netLayer != nil {
					flow := netLayer.NetworkFlow()
					if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
						tcp, _ := tcpLayer.(*layers.TCP)
						assembler.AssembleWithTimestamp(flow, tcp, packet.Metadata().Timestamp)
						//time.Sleep(time.Microsecond * 1)
						if DEBUG_METRICS {
							packet_count.Mark(1)
						}
					}
				}
			}
		case <-ticker:
			flushed, _ := assembler.FlushOlderThan(time.Now().Add(time.Second * -10))
			if DEBUG_METRICS {
				gr_gauge.Update(int64(runtime.NumGoroutine()))
				flushed_count.Mark(int64(flushed))
			}
		}
	}

done:
	if DEBUG_METRICS {
		metrics.WriteOnce(metrics.DefaultRegistry, os.Stdout)
	}
}
