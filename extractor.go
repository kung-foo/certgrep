package certgrep

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/mgutz/ansi"
	"github.com/olekukonko/tablewriter"
	"go.uber.org/zap"
)

const (
	//snaplen     = 65536
	maxAge         = 30 * time.Second
	dumpPackets    = false
	defaultDirPerm = 0755
)

var (
	redError    = ansi.ColorFunc("red+b")
	phosphorize = ansi.ColorFunc("166+h:black")
)

type Extractor struct {
	handle        *pcap.Handle
	logger        *zap.SugaredLogger
	verbose       bool
	bpf           string
	outputOptions outputOptions
	close         chan struct{}
	closeOnce     sync.Once
	logToStdout   bool
}

func NewExtractor(handle *pcap.Handle, options ...Option) (*Extractor, error) {
	e := &Extractor{
		handle: handle,
		close:  make(chan struct{}),
	}

	for _, option := range options {
		err := option(e)
		if err != nil {
			return nil, err
		}
	}

	return e, nil
}

func (e *Extractor) Close() {
	e.closeOnce.Do(func() {
		close(e.close)
	})
}

func (e *Extractor) Run() (err error) {
	packetSource := gopacket.NewPacketSource(e.handle, e.handle.LinkType())
	logFile := "extractor.log"
	if e.logToStdout {
		logLine = "-"
	}
	output, err := newOutput(logFile, e.outputOptions)
	if err != nil {
		return err
	}
	pool := tcpassembly.NewStreamPool(&readerFactory{
		logger: e.logger.Named("reader"),
		output: output,
	})
	assembler := tcpassembly.NewAssembler(pool)
	packets := packetSource.Packets()
	ticker := time.Tick(maxAge)

	e.logger.Infof("setting output dir to: %s", e.outputOptions.dir)

	var (
		lastFlush   time.Time
		firstPacket time.Time
		current     time.Time
		processed   int64
		c           int64
	)

	start := time.Now()

	for {
		select {
		case <-e.close:
			goto done
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				// TODO: find a better way to let flow workers finish
				time.Sleep(500 * time.Millisecond)
				//if Config.verbose {
				e.logger.Debugf("last packet, goodbye.")
				//}
				output.WaitUntilDone()
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

			if err := packet.ErrorLayer(); err != nil {
				//fmt.Println(err)
			} else {
				if netLayer := packet.NetworkLayer(); netLayer != nil {
					flow := netLayer.NetworkFlow()
					if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
						tcp, _ := tcpLayer.(*layers.TCP)
						if dumpPackets {
							e.logger.Debugf("%s\n%s", flow.String(), phosphorize(hex.Dump(tcpLayer.LayerPayload())))
						}
						assembler.AssembleWithTimestamp(flow, tcp, current)
						/*
							if Config.metrics {
								packetCount.Mark(1)
							}
						*/
					}
				}
			}

			if current.Sub(lastFlush) > maxAge {
				assembler.FlushOlderThan(lastFlush)
				lastFlush = current
				/*
					if Config.metrics {
						grGauge.Update(int64(runtime.NumGoroutine()))
						flushedCount.Mark(int64(flushed))
						doFlush.Mark(1)
					}
				*/
			}
		case <-ticker:
			assembler.FlushOlderThan(time.Now().Add(-1 * maxAge))
			/*
				if Config.metrics {
					grGauge.Update(int64(runtime.NumGoroutine()))
					flushedCount.Mark(int64(flushed))
					doFlush.Mark(1)
				}
			*/
		}
	}

done:
	e.logger.Infof("capture time: %.f seconds", current.Sub(firstPacket).Seconds())
	e.logger.Infof("capture size: %d bytes", processed)

	bps := 8 * (float64(processed) / current.Sub(firstPacket).Seconds())
	if bps < 1024*1024 {
		e.logger.Infof("average capture rate: %.3f Kbit/s", bps/1024)
	} else if bps < 1024*1024*1024 {
		e.logger.Infof("average capture rate: %.3f Mbit/s", bps/(1024*1024))
	} else {
		e.logger.Infof("average capture rate: %.3f Gbit/s", bps/(1024*1024*1024))
	}
	e.logger.Infof("pps: %.f", float64(c)/time.Now().Sub(start).Seconds())

	return
}

func PrintDeviceTable(out io.Writer, logger *zap.SugaredLogger) error {
	if runtime.GOOS == "linux" {
		if os.Geteuid() != 0 {
			logger.Info("Not all capture devices may be visible with your current user.")
		}
	}

	ifs, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

	if len(ifs) == 0 {
		me, _ := user.Current()
		return fmt.Errorf("No devices found. Does user \"%s\" have access?", me.Name)
	}
	tbl := tablewriter.NewWriter(out)
	tbl.SetHeader([]string{"name", "addresses", "description"})
	tbl.SetRowLine(true)

	for _, dev := range ifs {
		var addresses []string

		for _, a := range dev.Addresses {
			addresses = append(addresses, a.IP.String())
		}

		tbl.Append([]string{
			dev.Name,
			strings.Join(addresses, "\n"),
			dev.Description,
		})
	}

	tbl.Render()

	return nil
}
