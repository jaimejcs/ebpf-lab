package main

import (
	"bufio"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Alow BPF programs to be loaded
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	var objs sys_clone_ebpfObjects
	if err := loadSys_clone_ebpfObjects(&objs, nil); err != nil {
		log.Fatal("loading eBPF objects:", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("__x64_sys_clone", objs.HandleSysClone, nil)
	if err != nil {
		log.Fatal("attaching kprobe: ", err)
	}
	defer kp.Close()

	log.Println("eBPF program attached! Waiting for sys_clone...")

	f, err := os.Open("/sys/kernel/tracing/trace_pipe")
	if err != nil {
		log.Fatal("opening trace_pipe: ", err)
	}
	defer f.Close()

	//Exit on Ctrl+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)

	go func() {
		<-sig
		log.Println("Exiting...")
		os.Exit(0)
	}()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		log.Println(scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
