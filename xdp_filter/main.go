package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func ipToUint32(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip.To4())
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs xdp_filterObjects
	if err := loadXdp_filterObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName("wlo1")
	if err != nil {
		log.Fatal(err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilter,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attach failed:", err)
	}
	defer l.Close()

	// Add an IP to blocklist
	ip := net.ParseIP("192.168.1.5").To4()
	ipUint := ipToUint32(ip)
	block := uint8(1)
	if err := objs.BlockedIps.Put(ipUint, block); err != nil {
		log.Fatal("Failed to add blocked IP:", err)
	}

	log.Println("Blocking packets from 192.168.1.5")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Println("Shutting down...")
}
