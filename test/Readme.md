



## lcctest 介绍

lcctest提供了一键测试能力，保证 eBPF 工具能够在所有支持eBPF的内核上能够正常运行，避免客户使用工具出现运行不了的情况，提供给客户更好的体验。

### 为什么要有lcctest?

主要原因有三点：

1. libbpf CO-RE 能力：使用 CO-RE 则意味着需要考虑不同内核版本结构体的差异，但是这种差异只能在目标机运行 eBPF 程序时才能发现，所以提供了 lcctest，自动化地在每个内核版本运行 eBPF 程序;

2. 不同内核版本函数原型的差异，会导致 eBPF 程序 attach 出错；

3. 不同内核版本的 eBPF 功能/校验器差异，需要在开发期间能够发现这种差异。

### lcctest 使用方法

需要提供一个如下的配置文件，该配置文件包含了机器的信息及要运行的命令。然后运行 `lcctest --config <path-to-config>` 即可。

```
path = "/path/of/rtrace"
cmd = ["rtrace --proto icmp" , "rtrace --proto tcp"]

[[host]]
name = "centos 3.10"
ip = ""
usr = ""
pwd = ""

[[host]]
name = "alinux 2"
ip = ""
usr = ""
pwd = ""

[[host]]
name = "alinux 3"
ip = ""
usr = ""
pwd = ""
```