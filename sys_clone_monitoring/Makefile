PROJ_NAME=sys_clone_ebpf

BUILD=go build

BUILD_FLAGS=-o

DIR_GO=go generate

MOD=go mod

GET=go get

ECHO_LN=echo -e

all: setup import build


setup:
	@ $(ECHO_LN) "Initializing the module $(PROJ_NAME)...\n"
	$(MOD) init $(PROJ_NAME)
	$(MOD) tidy

import: setup
	@ $(ECHO_LN) "-- Importing dependencies --\n"
	$(GET) github.com/cilium/ebpf/cmd/bpf2go
	$(GET) github.com/cilium/ebpf/rlimit
	$(GET) github.com/cilium/ebpf/link

build: gen.go main.go
	$(DIR_GO)
	$(BUILD) $(BUILD_FLAGS) $(PROJ_NAME)

run: $(PROJ_NAME)
	@ $(ECHO_LN) "Starting application...\n"	
	sudo ./$(PROJ_NAME)

clean:
	rm -rf *bpfeb.go *bpfel.go *.o $(PROJ_NAME)


.PHONY=all build run setup