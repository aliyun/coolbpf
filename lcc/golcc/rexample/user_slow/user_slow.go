package main

import "C"

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	flag "github.com/spf13/pflag"
)

var (
	h    bool
	args TraceArgs
)

func init() {
	flag.BoolVar(&h, "h", false, "for help")
	flag.IntVar(&args.port, "dport", 22, "set trace dport")
	flag.IntVar(&args.delay, "delay", 100, "set trace packet time delay(us)")
}

type TraceArgs struct {
	port  int
	delay int
}

// More info can be added
type Trace struct {
	ts    uint64
	pid   uint32
	cpu1  uint32
	cpu2  uint32
	sport uint16
	dport uint16
}

func showTrace(data []byte) {
	var trace Trace
	/*
		panic here, no idea....
		err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &trace)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	*/
	trace.ts = binary.LittleEndian.Uint64(data[0:8])
	trace.pid = binary.LittleEndian.Uint32(data[8:12])
	trace.cpu1 = binary.LittleEndian.Uint32(data[12:16])
	trace.cpu2 = binary.LittleEndian.Uint32(data[16:20])
	trace.sport = binary.LittleEndian.Uint16(data[20:22])
	trace.dport = binary.LittleEndian.Uint16(data[22:24])
	ts := time.Now().Format("15:04:05")
	fmt.Printf("%8s ", ts)
	fmt.Printf("%-6d %-5d %-5d %-5d %-5d %-6d\n", trace.pid, trace.cpu1, trace.cpu2,
		trace.sport, trace.dport, trace.ts)
}

func initArgsMap(bpfModule *bpf.Module) error {
	var key int

	argsMap, err := bpfModule.GetMap("trace_args_map")
	if err != nil {
		return err
	}
	err = argsMap.UpdateValueFlags(unsafe.Pointer(&key), unsafe.Pointer(&args), 0)
	if err != nil {
		return err
	}

	return nil
}

func attachProgs(bpfModule *bpf.Module) error {
	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		if _, err := prog.AttachGeneric(); err != nil {
			return err
		}
	}
	return nil
}

func pollData(bpfModule *bpf.Module) {
	dataChan := make(chan []byte)
	lostChan := make(chan uint64)

	pb, err := bpfModule.InitPerfBuf("perf_map", dataChan, lostChan, 1)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	pb.Start()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer func() {
		pb.Stop()
		pb.Close()
		stop()
	}()
	fmt.Printf("%-8s %-6s %-6s %-5s %-5s %-5s %-5s\n",
		"TIME", "PID", "CPU1", "CPU2", "SPORT", "DPORT", "DELAY(us)")
loop:
	for {
		select {
		case data := <-dataChan:
			showTrace(data)
		case e := <-lostChan:
			fmt.Printf("Events lost:%d\n", e)
		case <-ctx.Done():
			break loop
		}
	}
}

func main() {

	flag.Parse()
	bpfModule, err := bpf.NewModuleFromFileArgs(bpf.NewModuleArgs{
		BPFObjPath: "user_slow.bpf.o",
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	if err := initArgsMap(bpfModule); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	if err := attachProgs(bpfModule); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	pollData(bpfModule)
}
