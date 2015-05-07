package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
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
	output      string
	json        bool
	der         bool
	yaml        bool
	verbose     bool
	veryVerbose bool
	metrics     bool
}

// global config struct
var Config = &config{}

var (
	packetCount  = metrics.NewMeter()
	grGauge      = metrics.NewGauge()
	flushedCount = metrics.NewMeter()
	doFlush      = metrics.NewMeter()

	redError    = ansi.ColorFunc("red+b")
	phosphorize = ansi.ColorFunc("166+h:black")
)

const (
	snaplen = 65536
	maxAge  = 30 * time.Second
)

// VERSION is set by the makefile
var VERSION = "0.0.0"

var usage = `
Usage:
    certgrep [options] [--format=<format> ...] [-v ...] (-p=<pcap> | -i=<interface>)
    certgrep -l | --list
    certgrep -h | --help | --version

Options:
    -h --help               Show this screen.
    --version               Show version.
    -p --pcap=<pcap>        PCAP file to parse
    -i --interface=<iface>  Network interface to listen on
    -l --list               List available interfaces
    -o --output=<output>    Output directory
    -f --format=<format>    Output format (json|yaml|der) [default: json]
    -b --bpf=<bpf>          Capture filter [default: tcp]
    --no-color              Disabled colored output
    -v                      Enable verbose logging (-vv for very verbose)
    --assembly-memuse-log
    --assembly-debug-log
    --dump-metrics
    --dump-packets
`

func main() {
	mainEx(os.Args[1:])
}

func mainEx(argv []string) {
	args, _ := docopt.Parse(usage, argv, true, VERSION, true)

	if args["--no-color"].(bool) {
		ansi.DisableColors(true)
	} else {
		if runtime.GOOS == "windows" {
			ansi.DisableColors(true)
		}
	}

	// little hack here to allow gopacket's debug flags to be set from the cmd line
	flagArgs := []string{}

	if args["--assembly-memuse-log"].(bool) {
		flagArgs = append(flagArgs, "-assembly_memuse_log")
	}
	if args["--assembly-debug-log"].(bool) {
		flagArgs = append(flagArgs, "-assembly_debug_log")
	}

	flag.CommandLine.Parse(flagArgs)

	Config.verbose = args["-v"].(int) > 0
	Config.veryVerbose = args["-v"].(int) > 1

	if Config.verbose {
		log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	}

	if args["--list"].(bool) {
		ifs, err := pcap.FindAllDevs()

		if err != nil {
			log.Fatal(err)
		}

		if len(ifs) == 0 {
			me, _ := user.Current()
			fmt.Printf("No devices found. Does user \"%s\" have access?\n", me.Name)
		} else {
			for i, dev := range ifs {
				fmt.Printf("%02d %-16s %s\n", i, dev.Name, dev.Description)
				for _, a := range dev.Addresses {
					fmt.Printf("   %s\n", a.IP)
				}
				fmt.Println()
			}
		}

		os.Exit(0)
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

	if Config.verbose {
		log.Printf("pcap_lib_version: %s", pcap.Version())
		log.Printf("LinkType: %s", handle.LinkType())
	}

	dumpPackets := args["--dump-packets"].(bool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	pool := tcpassembly.NewStreamPool(&readerFactory{})
	assembler := tcpassembly.NewAssembler(pool)

	//assembler.MaxBufferedPagesPerConnection = 8
	//assembler.MaxBufferedPagesTotal = 0

	packets := packetSource.Packets()
	ticker := time.Tick(maxAge)

	Config.metrics = args["--dump-metrics"].(bool)

	if Config.metrics {
		metrics.Register("packet_count", packetCount)
		packetCount.Mark(0)

		grGauge := metrics.NewGauge()
		metrics.Register("gr_gauge", grGauge)
		grGauge.Update(int64(runtime.NumGoroutine()))

		metrics.Register("flushed_count", flushedCount)
		flushedCount.Mark(0)

		metrics.Register("do_flush", doFlush)
		doFlush.Mark(0)

		go metrics.Log(metrics.DefaultRegistry, time.Second*5, log.New(os.Stderr, "metrics: ", log.Lmicroseconds))
	}

	var lastFlush time.Time
	var firstPacket time.Time
	var current time.Time
	var processed int64
	var c int64

	onSIGINT := make(chan os.Signal, 1)
	signal.Notify(onSIGINT, os.Interrupt)

	start := time.Now()

	for {
		select {
		case <-onSIGINT:
			goto done
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				// TODO: find a better way to let flow workers finish
				time.Sleep(500 * time.Millisecond)
				if Config.verbose {
					log.Print("last packet, goodbye.")
				}
				goto done
			}

			current = packet.Metadata().Timestamp
			processed += int64(len(packet.Data()))
			c++ // go is better

			// first packet
			if lastFlush.IsZero() {
				lastFlush = current
				firstPacket = current
			}

			if dumpPackets {
				log.Printf("%+v\n", packet)
			}

			if err := packet.ErrorLayer(); err != nil {
				//fmt.Println(err)
			} else {
				if netLayer := packet.NetworkLayer(); netLayer != nil {
					flow := netLayer.NetworkFlow()
					if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
						tcp, _ := tcpLayer.(*layers.TCP)
						if dumpPackets {
							fmt.Printf("%s\n\n", phosphorize(hex.Dump(tcpLayer.LayerPayload())))
						}
						assembler.AssembleWithTimestamp(flow, tcp, current)
						if Config.metrics {
							packetCount.Mark(1)
						}
					}
				}
			}

			if current.Sub(lastFlush) > maxAge {
				flushed, _ := assembler.FlushOlderThan(lastFlush)
				lastFlush = current
				if Config.metrics {
					grGauge.Update(int64(runtime.NumGoroutine()))
					flushedCount.Mark(int64(flushed))
					doFlush.Mark(1)
				}
			}
		case <-ticker:
			flushed, _ := assembler.FlushOlderThan(time.Now().Add(-1 * maxAge))
			if Config.metrics {
				grGauge.Update(int64(runtime.NumGoroutine()))
				flushedCount.Mark(int64(flushed))
				doFlush.Mark(1)
			}
		}
	}

done:
	log.Printf("capture time: %.f seconds", current.Sub(firstPacket).Seconds())
	log.Printf("capture size: %d bytes", processed)
	bps := 8 * (float64(processed) / current.Sub(firstPacket).Seconds())
	if bps < 1024*1024 {
		log.Printf("average capture rate: %.3f Kbit/s", bps/1024)
	} else if bps < 1024*1024*1024 {
		log.Printf("average capture rate: %.3f Mbit/s", bps/(1024*1024))
	} else {
		log.Printf("average capture rate: %.3f Gbit/s", bps/(1024*1024*1024))
	}
	log.Printf("pps: %.f", float64(c)/time.Now().Sub(start).Seconds())

	if Config.metrics {
		metrics.WriteOnce(metrics.DefaultRegistry, os.Stdout)
	}
}
