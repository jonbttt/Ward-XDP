// Command ward-xdp loads and attaches the Ward-XDP eBPF data plane and runs
// the userspace control plane
//
// Author: jonbttt (github.com/jonbttt)
// License: Apache-2.0 (see LICENSE); eBPF Programs are Dual BSD/GPL.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel ward ./bpf/ward.bpf.c -- -I./bpf

type wardEvent struct {
	Timestamp uint64
	IPSrc     [4]byte
	Verdict   int32
	Action    int32
	Reason    int32
	Value     uint64
}

func main() {
	ifaceName := flag.String("iface", "", "network interface to attach to")
	enforce := flag.Bool("enforce", false, "allows packet dropping when true")
	synMaxPkts := flag.Int("syn_max_pkts", 500, "number of packets to trigger SYN flood alert")
	synWindowNs := flag.Int("syn_window_ns", 5000000000, "timeframe for packets to trigger SYN flood alert (nanoseconds)")
	flag.Parse()

	if *ifaceName == "" {
		log.Fatal("[-] must specify -iface {network interface}")
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("[-] error looking up interface %q: %v", *ifaceName, err)
	}

	objs := wardObjects{}
	if err := loadWardObjects(&objs, nil); err != nil {
		log.Fatalf("[-] unable to load BPF objects: %+v", err)
	}
	defer objs.Close()

	cfg := wardWardCfg{
		Enforce:       0,
		SynMaxPackets: uint64(*synMaxPkts),
		SynWindowNs:   uint64(*synWindowNs),
	}
	if *enforce {
		cfg.Enforce = 1
	}
	if err := objs.WardConfig.Put(uint32(0), cfg); err != nil {
		log.Fatalf("[-] unable to set config: %v", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.WardMain,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		log.Printf("[~] driver mode failed: %v", err)
		log.Print("    trying generic...")
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.WardMain,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			log.Fatalf("[-] XDP attachment failed: %v", err)
		}
	}
	defer l.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("[-] unable to open ring buffer: %v", err)
	}
	defer reader.Close()

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}

				log.Printf("[-] error reading ring buffer: %v", err)
				continue
			}

			var event wardEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("[-] error decoding wardEvent: %v", err)
				continue
			}

			log.Printf("[!] src=%s reason=%d value=%d action=%d", net.IP(event.IPSrc[:]), event.Reason, event.Value, event.Action)
		}
	}()

	log.Printf("[+] successfully attached to interface %s, press Ctrl-C to detach", *ifaceName)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Print("\n")
	log.Println("[+] detaching...")
}
