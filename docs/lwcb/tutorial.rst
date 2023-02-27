


LightWeight CoolBPF tutorial
============================

一个 lwcb 程序主要有两部分构成，我们将结合下面的 lwcb 代码片段来进行说明：

* 探测类型 & 探测点： ``kprobe:tcp_drop`` 其中 ``kprobe`` 指明了探测类型，``tcp_drop`` 指明了探测点；
* 程序体：lwcb 语句语法与 ``C`` 类似，但有一些不同之处。比如，它无需定义变量类型，变量类型由 lwcb 进行推导。


注意： ``tcphdr、bswap、iphdr、ntop、timestr、ns、tcpflags、kstack`` 等是 lwcb 提供的简易 API，便于用户直接
在脚本里进行简单的数据处理，更多的 API 请见 reference

对于下面的 lwcb 程序，我们可以通过 ``./lwcb tcpdrop.cb`` 来运行它。

.. code-block:: c

    kprobe:tcp_drop {
        th = tcphdr(skb);
        sport = bswap(th->source);
        dport = bswap(th->dest);
        
        ih = iphdr(skb);
        sip = ntop(bswap(ih->saddr));
        dip = ntop(bswap(ih->daddr));
        
        state = tcpstate(sk->__sk_common.skc_state);
        print("%s ip: %s:%d -> %s:%d state: %s flags:%s %s\n", timestr(ns()), sip, sport, dip, dport, state, tcpflags(((u8 *)th)[13]), kstack());
    }


