# 1、项目简介
&emsp;[coolbpf](https://gitee.com/anolis/coolbpf) 是 [eBPF技术探索SIG](https://openanolis.cn/sig/ebpfresearch)下的项目之一，为开发者提供便捷的bpf技术实践平台，支持c/go/rust/lua/python等主流编程语言。本文以python为基础，引导bpf快速入门。

## 1.1、准备工作
1. 	Anolis/Alinux/Centos(7.6版本以上)内核环境，可访问公网，或者自建coolbpf服务也可以；
2. 环境已经安装python，2.7和3.X都可以，支持pip 安装包；
3. 掌握bpf 和 python 基本知识；

## 1.2、在龙蜥实验室中体验coolbpf
&emsp;用户可以在[龙蜥实验室](https://lab.openanolis.cn/#/apply/home)申请一台真实的机器，体验Anolis 和 coolbpf。申请步骤非常简单，直接注册即可。清单中的OS镜像均支持coolbpf，建议采用8以上版本。资源申请下来后，ssh 登录上去，先安装以下依赖包：

1. yum install -y python3 # python2 也支持，注意需要独立安装pip2
2. pip3 install coolbpf
3. yum install -y git 
4. git clone https://gitee.com/anolis/coolbpf.git

&emsp;通过上述步骤，coolbpf运行环境即已安装好。

# 2、coolbpf 入门
&emsp;coolbpf 入门代码放在 coolbpf/lcc/pylcc/guide/ 目录下，引导用户快速上手：

* hello.py # hello world
* eventOut.py     # 往用户态传递信息
* dynamicVar.py   # 动态修改代码
* hashMap.py  # hash map应用
*  callStack.py  # 获取调用栈的方法
*  codeSeparate.py/independ.bpf.c  #  独立bpf 文件实现

&emsp;注：上述实例是以钩取wake\_up\_new\_task 内核符号为例，这个符号在3.10内核上并没有实现，如果你要在3.10内核上验证，可以稍微修改下代码，将追踪符号替换成 wake\_up\_process 即可。

## 2.1、一切 hello wolrd 开始
&emsp;先秀代码：

```python
import time
from pylcc.lbcBase import ClbcBase

bpfPog = r"""
#include "lbc.h"

SEC("kprobe/wake_up_new_task")
int j_wake_up_new_task(struct pt_regs *ctx)
{
    struct task_struct* parent = (struct task_struct *)PT_REGS_PARM1(ctx);
    
    bpf_printk("hello lcc, parent: %d\n", _(parent->tgid));
    return 0;
}

char _license[] SEC("license") = "GPL";
"""

class Chello(ClbcBase):
    def __init__(self):
        super(Chello, self).__init__("hello", bpf_str=bpfPog)
        while True:
            time.sleep(1)

if __name__ == "__main__":
    hello = Chello()
    pass
```

### 2.1.1、bpf部分代码：

* bpf代码包含 lbc.h 头文件即可，该头文件会包含以下头文件，并且会加上我们常见的宏定义和数据类型：

```C
#include "vmlinux.h"
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
```
* SEC的定义和函数内部实现与libbpf应用方法保持一致；
* 访问结构体成员使用了_宏，该方法访问方式相对固定，下一节会提供core的获取方法；
* 末尾不要遗漏 _license声明

### 2.1.2、python代码:
&emsp;python 部分代码从ClbcBase 类继承，__init__函数中，第一入参必须要指定，用于指定生成so的文件名。在执行完__init__函数后，bfp模块就已经注入到内核当中执行。

### 2.1.3、执行结果
&emsp;执行 python2 hello.py 运行，并在新的窗口查看调试信息输出：

```bash
#cat /sys/kernel/debug/tracing/trace_pipe
           <...>-1091294 [005] d... 17658161.425644: : hello lcc, parent: 106880
           <...>-4142485 [003] d... 17658161.428568: : hello lcc, parent: 4142485
           <...>-4142486 [002] d... 17658161.430972: : hello lcc, parent: 4142486
           <...>-4142486 [002] d... 17658161.431228: : hello lcc, parent: 4142486
           <...>-4142486 [002] d... 17658161.431557: : hello lcc, parent: 4142486
           <...>-4142485 [003] d... 17658161.435385: : hello lcc, parent: 4142485
           <...>-4142490 [000] d... 17658161.437562: : hello lcc, parent: 4142490
```

&emsp;在当前目录下新增了hello.so 文件，如果文件时间戳有更新，只要bpfProg部分内容不发生改变，就不会触发重编动作。如果bpfProg 发生变换，就会触发重新编译动作，生成新的so。用户可以尝试修改打印信息验证一下。

## 2.2、通过perf\_event往用户态传递信息
&emsp;代码：

```python
from pylcc.lbcBase import ClbcBase

bpfPog = r"""
#include "lbc.h"
#define TASK_COMM_LEN 16
struct data_t {
    u32 c_pid;
    u32 p_pid;
    char c_comm[TASK_COMM_LEN];
    char p_comm[TASK_COMM_LEN];
};

LBC_PERF_OUTPUT(e_out, struct data_t, 128);
SEC("kprobe/wake_up_new_task")
int j_wake_up_new_task(struct pt_regs *ctx)
{
    struct task_struct* parent = (struct task_struct *)PT_REGS_PARM1(ctx);
    struct data_t data = {};

    data.c_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.c_comm, TASK_COMM_LEN);
    data.p_pid = BPF_CORE_READ(parent, pid);
    bpf_core_read(&data.p_comm[0], TASK_COMM_LEN, &parent->comm[0]);
    
    bpf_perf_event_output(ctx, &e_out, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class CeventOut(ClbcBase):
    def __init__(self):
        super(CeventOut, self).__init__("eventOut", bpf_str=bpfPog)

    def _cb(self, cpu, data, size):
        e = self.getMap('e_out', data, size)
        print("current pid:%d, comm:%s. wake_up_new_task pid: %d, comm: %s" % (
            e.c_pid, e.c_comm, e.p_pid, e.p_comm
        ))

    def loop(self):
        self.maps['e_out'].open_perf_buffer(self._cb)
        try:
            self.maps['e_out'].perf_buffer_poll()
        except KeyboardInterrupt:
            print("key interrupt.")
            exit()


if __name__ == "__main__":
    e = CeventOut()
    e.loop()
```
### 2.2.1、libbpf部分代码：
* LBC\_PERF\_OUTPUT宏不能用原有的bpf\_map\_def ……BPF\_MAP\_TYPE\_PERF\_EVENT\_ARRAY…… 替代，虽然是同样申明一个 perf maps，但如果用原始的声明方式，python在加载的时候将无法识别出对应的内核数据类型。
* 可以使用 bpf\_get\_current\_pid\_tgid 等libbpf helper函数；
* 可以使用 bpf\_core\_read 等方法，达到一次编译，处处运行；
* 不可使用 bcc 独有的方法，如直接指针访问变量等；

### 2.2.2、python部分代码：
&emsp;loop函数为入口：

* self.maps['e\_out'].open\_perf\_buffer(self.\_cb)函数是为 e\_out事件注册回调钩子函数，其中e\_out命名与bpfProg中LBC\_PERF\_OUTPUT(e\_out, struct data\_t, 128) 对应；
* self.maps['e\_out'].perf\_buffer\_poll() 即poll 对应的event事件，与bpfProg中 bpf\_perf\_event\_output(ctx, &e\_out……对应；

&emsp;接下来看\_cb 回调函数：

* e = self.getMap('e\_out', data, size) 将数据流生成对应的数据对象；
* 生成了数据对象后，就可以通过成员的方式来访问数据对象，该对象成员与bpfProg中 struct data\_t 定义保持一致

### 2.2.3、执行结果
```bash
python3 eventOut.py
current pid:241808, comm:python. wake_up_new_task parent pid: 241871, comm: python
current pid:1, comm:systemd. wake_up_new_task parent pid: 1, comm: systemd
……
```

## 2.3、动态修改bpf部分代码
&emsp;动态适配是诸如python、lua等动态语言的灵魂特性。该示例主要展现了coolbpf的动态特性，大部分代码与eventOut.py一致。主要差异在bpfProg代码添加了过滤动作：

```C
……
	u32 pid = BPF_CORE_READ(parent, pid);
    if (pid != FILTER_PID) {
        return 0;
    }
……
```
在main入口处进行了pid替换：

```python
……
if __name__ == "__main__":
    bpfPog = bpfPog.replace("FILTER_PID", sys.argv[1])
    e = CdynamicVar()
    e.loop
```

将要过滤的pid作为参数传入，执行效果：

```
python3 dynamicVar.py 241871
current pid:241808, comm:python. wake_up_new_task pid: 241871, comm: python
current pid:241808, comm:python. wake_up_new_task pid: 241871, comm: python
current pid:241808, comm:python. wake_up_new_task pid: 241871, comm: python
```

## 2.4、hash map应用
&emsp;与perf_event需要用户态不断同步轮询的方法不同，maps作为libbpf内置的数据类型，内核态可以直接访问和操作maps数据，用户态进行异步查询即可。

### 2.4.1、bpf部分代码

&emsp;示例代码中定位hash map的方法：

```C
LBC_HASH(pid_cnt, u32, u32, 1024);
```

使用方法与libbpf 一致：

```C
u32 *pcnt, cnt;
    
    pcnt =  bpf_map_lookup_elem(&pid_cnt, &pid);
    cnt  = pcnt ? *pcnt + 1 : 1;     // 为了确保原子性，推荐 __sync_fetch_and_add 方法
    bpf_map_update_elem(&pid_cnt, &pid, &cnt, BPF_ANY);
```
### 2.4.2、python部分代码
&emsp;查询maps的位置在exit退出之前打印所有信息

```python
……
            dMap = self.maps['pid_cnt']
            print(dMap.get())
            exit()
```
&emsp;哈希表对象可以直接由 self.maps['pid\_cnt'] 方法获取到，可以调用get函数，获取到dict对象。
&emsp; 除了BPF\_MAP\_TYPE\_HASH，lcc当前还支持BPF\_MAP\_TYPE\_LRU\_HASH、BPF\_MAP\_TYPE\_PERCPU\_HASH、 BPF\_MAP\_TYPE\_LRU\_PERCPU\_HASH等类型，更多类型支持在完善中，敬请期待。

### 2.4.3、注意点
&emsp;hash map key 应该是是可哈希类型的，如int等，不能为dict（对应自定义结构体）

## 2.5 call stack获取
&emsp;获取内核调用栈是bpf一项非常重要的调试功能，参考 callStack.py，大部分代码与eventOut.py一致。

### 2.5.1、bpf部分
&emsp;吐出的数据结构体中增加stack\_id成员：

```python
struct data_t {
    u32 c_pid;
    u32 p_pid;
    char c_comm[TASK_COMM_LEN];
    char p_comm[TASK_COMM_LEN];
    u32 stack_id;
};

LBC_PERF_OUTPUT(e_out, struct data_t, 128);
LBC_STACK(call_stack,32);
```

&emsp;在处理函数中记录call stack

```
data.stack_id = bpf_get_stackid(ctx, &call_stack, KERN_STACKID_FLAGS);
```

### 2.5.2、 python部分
&emsp;通过getStacks传入的stack\_id，即可获取调用栈符号数组，然后列出来即可

```python
		stacks = self.maps['call_stack'].getStacks(e.stack_id)
		print("call trace:")
		for s in stacks:
			print(s)
```

### 2.5.3、执行结果

```python
python callStack.py
remote server compile success.
current pid:1, comm:systemd. wake_up_new_task pid: 1, common: systemd
call trace:
startup_64
do_syscall_64
entry_SYSCALL_64_after_swapgs
```

## 2.7、py与bpf.c文件分离
&emsp;参考 codeSeparate.py 和 independ.bpf.c，它的功能实现和eventOut.py 完全一致，不一样的是将python和bpf.c的功能拆分到了两个文件中去实现。  我们只需要关注下\_\_init\_\_函数

```python
def __init__(self):
        super(codeSeparate, self).__init__("independ")
```
&emsp;它没有了 bpf\_str 入参，此时pylcc会尝试从当前目录上下，去找independ.bpf.c文件并提请编译加载。不同类型代码分开管理，适合大型开发项目。

# 3、总结与展望
&emsp;coolbpf中的pylcc具备依赖资源少、低代码量实现、无搭建复杂的编译工程门槛、用户容易上手等优势。有相关内核及编程技术的同学可以在极短时间内上手开发。
&emsp;[BCC](https://github.com/iovisor/bcc)优势在于它的工具资源极其丰富，当前coolbpf也有一部分实现，[链接](https://gitee.com/anolis/surftrace/tree/master/tools/pylcc/pytool)。也欢迎各位同学为该SIG提供建议和丰富coolbpf应用。
