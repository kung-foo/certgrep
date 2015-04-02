package main

import (
	"github.com/docopt/docopt-go"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

var VERSION string

func main() {
	usage := `
Usage:
    certdumper [options] -p=<pcap>
    certdumper [options] -i=<interface>
    certdumper -h | --help | --version

Options:
    -h --help               Show this screen.
    --version               Show version.
    -p --pcap=<pcap>        PCAP file to parse
    -i --interface=<iface>  Network interface to listen on
    -v                      Enable verbose logging.
`

	args, _ := docopt.Parse(usage, nil, true, VERSION, true)

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
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	pool := tcpassembly.NewStreamPool(&ReaderFactory{})
	assembler := tcpassembly.NewAssembler(pool)

	for packet := range packetSource.Packets() {
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
	}
}
