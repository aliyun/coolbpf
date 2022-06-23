package main

import "C"

import (
	"fmt"
	"github.com/aquasecurity/libbpfgo"
	"os"
	"time"
)

func main() {

	bpfModule, err := libbpfgo.NewModuleFromFile("hello.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	bpfModule.ListProgramNames()
	prog1, err := bpfModule.GetProgram("j_wake_up_new_task")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	link1, err := prog1.AttachGeneric()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	if link1.GetFd() == 0 {
		os.Exit(-1)
	}

	fmt.Println(prog1.GetType().String())
	time.Sleep(10000 * time.Second)
}
