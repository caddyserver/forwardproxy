package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"github.com/miekg/pcap"
	"log"
	"os"
	"runtime/pprof"
	"strings"
)

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")

func safeParse(msg *dns.Msg, data []byte) (err error) {
	defer func() {
		if e := recover(); e != nil {
			fmt.Fprintf(os.Stderr, "Crashed dns: %v\nError: %v\n",
				hex.EncodeToString(data), e)
			err = fmt.Errorf("bad packet")
		}
	}()
	return msg.Unpack(data)
}

func main() {
	flag.Parse()
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	fileName := flag.Arg(0)

	pcapfile, err := pcap.OpenOffline(fileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open pcap file %#v: %v\n",
			fileName, err)
		os.Exit(1)
	}

	w := bufio.NewWriter(os.Stdout)

	i := uint(0)
	for pkt := pcapfile.Next(); pkt != nil; pkt = pcapfile.Next() {
		i += 1
		pkt.Decode()
		var msg dns.Msg

		if err := safeParse(&msg, pkt.Payload); err != nil {
			//fmt.Fprintf(os.Stderr, "err %v\n", err)
			continue
		}

		if len(msg.Question) != 1 {
			continue
		}

		// if msg.MsgHdr.Response == true {
		// 	continue
		// }

		qname := msg.Question[0].Name
		qname = qname[:len(qname)-1]
		fmt.Fprintf(w, "%s, %s\n", pkt.Time, strings.ToLower(qname))
	}

	w.Flush()
	fmt.Fprintf(os.Stderr, "Parsed %d packets\n", i)
}
