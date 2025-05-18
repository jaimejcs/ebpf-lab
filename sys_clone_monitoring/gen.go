package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux sys_clone_ebpf pkg/sys_clone_ebpf.c -- -I/usr/src/linux-headers-6.1.0-34-amd64/include -I/usr/include/x86_64-linux-gnu
