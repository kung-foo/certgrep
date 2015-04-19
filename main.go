package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
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
	output       string
	json         bool
	der          bool
	yaml         bool
	verbose      bool
	very_verbose bool
	metrics      bool
}

var Config = &config{}

var bmap = make([][]int, 256)
var bmap_mtx = sync.RWMutex{}

var (
	packet_count  = metrics.NewMeter()
	gr_gauge      = metrics.NewGauge()
	flushed_count = metrics.NewMeter()
	do_flush      = metrics.NewMeter()
)

const (
	snaplen = 65536
	max_age = 10 * time.Second
)

var VERSION string
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

	Config.verbose = args["-v"].(int) > 0
	Config.very_verbose = args["-v"].(int) > 1

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

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	pool := tcpassembly.NewStreamPool(&ReaderFactory{})
	assembler := tcpassembly.NewAssembler(pool)

	//assembler.MaxBufferedPagesPerConnection = 8
	//assembler.MaxBufferedPagesTotal = 0

	packets := packetSource.Packets()
	ticker := time.Tick(max_age)

	Config.metrics = args["--dump-metrics"].(bool)

	if Config.metrics {
		metrics.Register("packet_count", packet_count)
		packet_count.Mark(0)

		gr_gauge := metrics.NewGauge()
		metrics.Register("gr_gauge", gr_gauge)
		gr_gauge.Update(int64(runtime.NumGoroutine()))

		metrics.Register("flushed_count", flushed_count)
		flushed_count.Mark(0)

		metrics.Register("do_flush", do_flush)
		do_flush.Mark(0)

		go metrics.Log(metrics.DefaultRegistry, time.Second*5, log.New(os.Stderr, "metrics: ", log.Lmicroseconds))
	}

	var last_flush time.Time
	var first_packet time.Time
	var current time.Time
	var processed int64
	var c int64

	on_SIGINT := make(chan os.Signal, 1)
	signal.Notify(on_SIGINT, os.Interrupt)

	start := time.Now()

	for {
		select {
		case <-on_SIGINT:
			goto done
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				if Config.verbose {
					log.Print("last packet, goodbye.")
				}
				goto done
			}

			current = packet.Metadata().Timestamp
			processed += int64(len(packet.Data()))
			c++

			// first packet
			if last_flush.IsZero() {
				last_flush = current
				first_packet = current
			}

			if Config.very_verbose {
				log.Printf("%+v\n", packet)
			}

			if err := packet.ErrorLayer(); err != nil {
				//fmt.Println(err)
			} else {
				if netLayer := packet.NetworkLayer(); netLayer != nil {
					flow := netLayer.NetworkFlow()
					if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
						tcp, _ := tcpLayer.(*layers.TCP)
						assembler.AssembleWithTimestamp(flow, tcp, current)
						if Config.metrics {
							packet_count.Mark(1)
						}
					}
				}
			}

			if current.Sub(last_flush) > max_age {
				flushed, _ := assembler.FlushOlderThan(last_flush)
				last_flush = current
				if Config.metrics {
					gr_gauge.Update(int64(runtime.NumGoroutine()))
					flushed_count.Mark(int64(flushed))
					do_flush.Mark(1)
				}
			}
		case <-ticker:
			flushed, _ := assembler.FlushOlderThan(time.Now().Add(-1 * max_age))
			if Config.metrics {
				gr_gauge.Update(int64(runtime.NumGoroutine()))
				flushed_count.Mark(int64(flushed))
				do_flush.Mark(1)
			}
		}
	}

done:
	log.Printf("capture time: %.f seconds", current.Sub(first_packet).Seconds())
	log.Printf("capture size: %d bytes", processed)
	bps := 8 * (float64(processed) / current.Sub(first_packet).Seconds())
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
