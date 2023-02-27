




LightWeight CoolBPF reference
=============================

lwcb 参考手册

1. 使用说明
-----------------


单行命令
^^^^^^^^^^^^^^

``lwcb -t`` 可以直接运行单条命令形式的 eBPF 程序，如：

.. code-block:: shell 
    
    lwcb -t 'kprobe:tcp_rcv_established {print("%s :triggerred by tcp_rcv_established\n", timestr(ns()));}'


lwcb 脚本
^^^^^^^^^

``lwcb <脚本路径>`` 可以运行 lwcb 脚本 


2. 语法说明
-----------------

lwcb 的语法和 c 语言非常类似，

- { } ： 是一个代码块

- // ：是注释

- "string" ：是字符串 

- -> 或 .：取结构体成员

- `` if {} else {} ``：if 语句

- ``return``：返回语句 

- ``[]``：数组索引或者是 eBPF map 查找


3. 探测类型
-----------------

目前支持的探测类型有：

- k(ret)probe： BPF_PROG_TYPE_KPROBE

后续需要支持的探测类型有：

- tracepoint： BPF_PROG_TYPE_TRACEPOINT

- raw tracepoint：BPF_PROG_TYPE_RAW_TRACEPOINT

- syscall： BPF_PROG_TYPE_SYSCALL

- perf event：BPF_PROG_TYPE_PERF_EVENT

4. MAP 类型
-----------------

目前支持的 eBPF map 类型有：

- BPF_MAP_TYPE_PERF_EVENT_ARRAY

- BPF_MAP_TYPE_HASH

后续需要支持的 eBPF map 类型有：

- BPF_MAP_TYPE_ARRAY

- BPF_MAP_TYPE_PERCPU_HASH

- BPF_MAP_TYPE_PERCPU_ARRAY

- BPF_MAP_TYPE_RINGBUF： 如果内核版本支持 ringbuffer 的话，我们应该用 ringbuffer 替代 perf buffer


5. 内置函数
-----------------

print 
^^^^^^^^

语法： ``print(fmt, args)``


iphdr
^^^^^^^^

语法： ``iphdr(skb)``


tcphdr
^^^^^^^^

语法： ``tcphdr(skb)``

ntop
^^^^^^^^

语法： ``ntop(i32 addr)``

bswap
^^^^^^^^

语法： ``bswap(u8 | i8 | u16 | i16 | u32 | i32 | u64 | i64)``

kstack
^^^^^^^^

语法： ``kstack(i32 depth) | kstack()``

ns
^^^^^^^^

语法： ``ns()``

pid
^^^^^^^^

语法： ``pid()``

tcpstate
^^^^^^^^

语法： ``tcpstate(i32 tcpstate)``

tcpflags
^^^^^^^^

语法： ``tcpstate(i32 tcpflags)``

timestr
^^^^^^^^

语法： ``timestr(u64 ts)``

ksym
^^^^^^^^

语法： ``ksym(u64 kernel_address)``

reg
^^^^^^^^

语法： ``reg(string)``

6. 内置常量
-----------------

linux 内核包含了大量的宏常量，比如 ``#define IPPROTO_TCP 6`` 。 为此，lwcb 也提供了这些宏常量，使得
用户在写 lwcb 脚本代码时，能够用到内核常用的宏常量。目前已经支持的宏常量如下：

- IPPROTO_IP
- IPPROTO_TCP
- IPPROTO_ICMP
- IPPROTO_UDP

也欢迎大家贡献更多的宏常量，相关代码请参考：``lwcb/src/cmacro.rs``

