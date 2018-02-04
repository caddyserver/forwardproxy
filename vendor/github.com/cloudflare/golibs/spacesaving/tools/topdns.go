package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"github.com/cloudflare/golibs/spacesaving"
	"github.com/miekg/dns"
	"github.com/miekg/pcap"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

func safeParse(msg *dns.Msg, data []byte) (err error) {
	defer func() {
		if e := recover(); e != nil {
			hexs := hex.EncodeToString(data)
			fmt.Fprintf(os.Stderr, "Crashed dns: %v\nError: %v\n",
				hexs, e)
			panic("Unpacking dns crashed: " + hexs)
		}
	}()
	return msg.Unpack(data)
}

func main() {
	var (
		pc  *pcap.Pcap
		err error
	)
devloop:
	for _, device := range []string{"bond0", "eth2", "en0", "any"} {
		devs, errx := pcap.FindAllDevs()
		if errx != "" {
			log.Fatalf("%v", errx)
		}
		for _, dev := range devs {
			if dev.Name == device {
				pc, err = pcap.OpenLive(device, 8192, false, 1000)
				if err == nil {
					break devloop
				}
			}
		}
	}

	if err != nil {
		log.Fatalf("%v", err)
	}

	if err = pc.SetFilter("udp and dst port 53"); err != nil {
		log.Fatalf("%v", err)
	}

	lock := &sync.Mutex{}
	ss := &spacesaving.Rate{}
	ss.Init(4096, 60*time.Second)

	go Poller(lock, ss, pc)

	for pkt, r := pc.NextEx(); r >= 0; pkt, r = pc.NextEx() {
		if r == 0 {
			continue
		}
		pkt.Decode()
		var msg dns.Msg
		if err := safeParse(&msg, pkt.Payload); err != nil {
			fmt.Printf("err %v\n", err)
			continue
		}

		qname := strings.ToLower(msg.Question[0].Name)
		if len(qname) > 0 {
			qname = qname[:len(qname)-1]
		}

		lock.Lock()
		ss.Touch(qname, pkt.Time)
		lock.Unlock()
	}

	fmt.Printf("Done\n")
}

func Poller(lock *sync.Mutex, ss *spacesaving.Rate, pc *pcap.Pcap) {
	w := bufio.NewWriter(os.Stdout)

	for _ = range time.Tick(3 * time.Second) {
		stat, _ := pc.Getstats()

		lock.Lock()
		fmt.Fprintf(w, "\033c")
		elements := ss.GetAll(time.Now())
		for i, e := range elements {
			fmt.Fprintf(w, "%60s\t%f\t%f\n", e.Key, e.LoRate, e.HiRate)
			if i > 40 {
				break
			}
		}
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "received:%v  dropped:%v/%v (software/interface)\n",
			stat.PacketsReceived, stat.PacketsDropped, stat.PacketsIfDropped)
		w.Flush()
		lock.Unlock()
	}
}
