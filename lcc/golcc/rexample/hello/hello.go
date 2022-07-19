package main

import "C"

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aquasecurity/libbpfgo"
	"golang.org/x/sys/unix"
)

var (
	h    bool
	path string
)

func init() {
	var name unix.Utsname
	unix.Uname(&name)
	defaultPath := fmt.Sprintf("/boot/vmlinux-%s", name.Release)
	defaultPath = strings.Trim(defaultPath, "\x00")

	flag.BoolVar(&h, "h", false, "this help")
	flag.StringVar(&path, "p", defaultPath, "set BTF custom path")
}

func main() {

	flag.Parse()
	fmt.Println("btf path:", path)
	bpfModule, err := libbpfgo.NewModuleFromFileArgs(libbpfgo.NewModuleArgs{
		BPFObjPath: "hello.bpf.o",
		BTFObjPath: path,
	})
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
