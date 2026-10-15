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
	"strings"
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
	synBlockTTL := flag.Int("syn_block_ttl_ns", 60000000000, "how long to block a SYN flood source (nanoseconds)")
	scanMaxPorts := flag.Int("scan_max_ports", 20, "number of distinct ports to trigger port scan alert (<64 due to bitmap)")
	scanWindowNs := flag.Int("scan_window_ns", 5000000000, "timeframe for ports accessed to trigger port scan alert (nanoseconds)")
	scanBlockTTL := flag.Int("scan_block_ttl_ns", 600000000000, "how long to block a port scan source (nanoseconds)")
	allowList := flag.String("allow", "", "comma-delimited IPs that are never blocked")
	arpStrict := flag.Bool("arp_strict", false, "drop ARP replies from IPs not in trust table")
	arpTrust := flag.String("arp_trust", "", "comma-delimited IP=MAC pairs, ex: 10.0.0.1=aa:bb:cc:dd:ee:ff")
	flag.Parse()

	if *ifaceName == "" {
		log.Fatal("[-] must specify -iface {network interface}")
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("[-] error looking up interface %q: %v", *ifaceName, err)
	}

	if *scanMaxPorts <= 0 || *scanMaxPorts >= 64 {
		log.Fatalf("[-] scan_max_ports must be < 64")
	}

	objs := wardObjects{}
	if err := loadWardObjects(&objs, nil); err != nil {
		log.Fatalf("[-] unable to load BPF objects: %+v", err)
	}
	defer objs.Close()

	cfg := wardWardCfg{
		Enforce:            0,
		SynMaxPackets:      uint64(*synMaxPkts),
		SynWindowNs:        uint64(*synWindowNs),
		SynBlockTtlNs:      uint64(*synBlockTTL),
		PortScanMaxPorts:   uint64(*scanMaxPorts),
		PortScanWindowNs:   uint64(*scanWindowNs),
		PortScanBlockTtlNs: uint64(*scanBlockTTL),
		ArpStrict:          0,
	}
	if *enforce {
		cfg.Enforce = 1
	}
	if *arpStrict {
		cfg.ArpStrict = 1
	}
	if err := objs.WardConfig.Put(uint32(0), cfg); err != nil {
		log.Fatalf("[-] unable to set config: %v", err)
	}

	if *allowList != "" {
		for _, s := range strings.Split(*allowList, ",") {
			ip := net.ParseIP(strings.TrimSpace(s)).To4()
			if ip == nil {
				log.Fatalf("[-] invalid IPv4 in -allow: %q", s)
			}
			if err := objs.WardAllowlist.Put([4]byte(ip), uint8(1)); err != nil {
				log.Fatalf("[-] unable to add %s to allowlist: %v", ip, err)
			}
			log.Printf("[+] added %s to allowlist", ip)
		}
	}

	if *arpTrust != "" {
		for _, pair := range strings.Split(*arpTrust, ",") {
			parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(parts) != 2 {
				log.Fatalf("[-] invalid -arp_trust entry (expected ip=mac): %q", pair)
			}
			ip := net.ParseIP(parts[0]).To4()
			if ip == nil {
				log.Fatalf("[-] invalid IPv4 in -arp_trust: %q", parts[0])
			}
			mac, err := net.ParseMAC(parts[1])
			if err != nil {
				log.Fatalf("[-] invalid MAC in -arp_trust: %q", parts[1])
			} else if len(mac) != 6 {
				log.Fatalf("[-] invalid MAC length in -arp_trust (ethernet only): %q", parts[1])
			}
			var val [8]byte
			copy(val[:], mac)
			if err := objs.ArpTrust.Put([4]byte(ip), val); err != nil {
				log.Fatalf("[-] unable to add %s to ARP trust table: %v", ip, err)
			}
			log.Printf("[+] trusting %s at %s", ip, mac)
		}
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

			if event.Reason == 3 || event.Reason == 4 {
				var b [8]byte
				binary.LittleEndian.PutUint64(b[:], event.Value)
				log.Printf("[!] src=%s reason=%d mac=%s action=%d", net.IP(event.IPSrc[:]), event.Reason, net.HardwareAddr(b[:6]), event.Action)
			} else {
				log.Printf("[!] src=%s reason=%d value=%d action=%d", net.IP(event.IPSrc[:]), event.Reason, event.Value, event.Action)
			}
		}
	}()

	log.Printf("[+] successfully attached to interface %s, press Ctrl-C to detach", *ifaceName)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Print("\n")
	log.Println("[+] detaching...")
}
