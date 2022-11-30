LCC=coolbpf
CC=gcc
PRG=user_slow
BPF_FILE=$(PRG).bpf.c
BPF_ORIFILE=bpf/$(PRG).bpf.c
BPF_O=$(PRG).bpf.o
PWD := $(shell pwd)
GO_CFLAGS="-I $(PWD)/../../include"
GO_LDFLAGS="$(PWD)/../../lib/libbpf.a"

$(PRG): $(BPF_O)
	CGO_CFLAGS=$(GO_CFLAGS) CGO_LDFLAGS=$(GO_LDFLAGS) go build -o $(PRG)

$(BPF_O): $(BPF_ORIFILE)
	cp $(PWD)/$(BPF_ORIFILE) $(PWD)
	$(LCC) -f $(BPF_FILE) -o
	rm -f $(PWD)/$(BPF_FILE)

.PRONY:clean
clean:
	rm -f $(PRG) $(BPF_O)