package main

import (
	"os"
	"sync"
	"time"

	"github.com/docopt/docopt-go"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

var bmap = make([][]int, 256)
var bmap_mtx = sync.RWMutex{}

var VERSION string
var usage = `
Usage:
    certgrep [options] -p=<pcap>
    certgrep [options] -i=<interface>
    certgrep -h | --help | --version

Options:
    -h --help               Show this screen.
    --version               Show version.
    -p --pcap=<pcap>        PCAP file to parse
    -i --interface=<iface>  Network interface to listen on
    -v                      Enable verbose logging.
`

func main() {
	mainEx(os.Args[1:])
}

func mainEx(argv []string) {
	//defer profile.Start(profile.CPUProfile).Stop()
	/*
		for i, _ := range bmap {
			bmap[i] = make([]int, 256)
		}

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			<-c
			log.Printf("\n\n\n")
			for i, v := range bmap {
				var max_c = 0
				var max_j = 0
				for j, c := range v {
					if c > max_c {
						max_c = c
						max_j = j
					}
				}

				if i < 32 {
					log.Printf("%02d 0x%02X %d\n", i, max_j, max_c)
				}
			}
			os.Exit(0)
		}()
	*/
	args, _ := docopt.Parse(usage, argv, true, VERSION, true)

	var handle *pcap.Handle
	var err error

	if args["--pcap"] != nil {
		handle, err = pcap.OpenOffline(args["--pcap"].(string))
		if err != nil {
			panic(err)
		}
	}

	if args["--interface"] != nil {
		handle, err = pcap.OpenLive(args["--interface"].(string), 1600, true, pcap.BlockForever)
		if err != nil {
			panic(err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	pool := tcpassembly.NewStreamPool(&ReaderFactory{})
	assembler := tcpassembly.NewAssembler(pool)

	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)

	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}
			if err := packet.ErrorLayer(); err != nil {
				//fmt.Println(err)
			} else {
				if netLayer := packet.NetworkLayer(); netLayer != nil {
					flow := netLayer.NetworkFlow()
					if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
						tcp, _ := tcpLayer.(*layers.TCP)
						assembler.AssembleWithTimestamp(flow, tcp, packet.Metadata().Timestamp)
					}
				}
			}
		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}
