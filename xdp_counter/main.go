package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove te limits for kernel (kernels < 5.11)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock: ", err)
	}

	// Load the compiled eBPF ELF into the kernel
	var objs counterObjects
	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects: ", err)
	}
	defer objs.Close()

	// TODO: turn this ifname call dynamic
	// I am using the wireless interface for development
	// Loopback interface can count the packets in duplicate or drop them (see documentation of xdp for your distro/kernel)
	ifname := "wlo1"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Interface %s: %s", ifname, err)
	}

	// Attaching the xdp_count_packets to the specified interface
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpCountPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XPD:", err)
	}
	defer link.Close()

	// Logging the start
	log.Printf("Starting the counter in interface %s", ifname)

	// Fetching the packet counter from pkt_count
	// Exit the program with some interruption
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	for {
		select {
		case <-tick:
			var count uint64
			err := objs.PktCount.Lookup(uint32(0), &count)
			if err != nil {
				log.Fatal("MAp lookup: ", err)
			}
			log.Printf("Received %d packets", count)
		case <-stop:
			log.Println("Exiting the program...")
			return
		}
	}
}
