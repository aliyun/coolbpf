pylwcb tutorial
===============

pylwcb 是 lwcb 的 python 模块。我们可以利用它来进行开发 eBPF 程序，然后使用 python 进行复杂的
数据处理。


1. hello world
---------------

通过 ``import pylwcb`` 导入 pylwcb 模块。 我们提供了一个简单的 say_hello 方法，该方法会打印
出 ``hello from pylwcb modules`` 字样。

.. code-block:: python 

    import pylwcb 
    print(pylwcb.say_hello())



2. 一个简单的 pylwcb 程序 
--------------------------------------

下面是一个结合了 lwcb 脚本代码的 pylwcb 程序。 


.. code-block:: python 
    
    import pylwcb
    lwcb_program = """
    kprobe:tcp_rcv_established {
        th = tcphdr(skb);
        ih = iphdr(skb);
        print(ntop(bswap(ih->saddr)), ntop(bswap(ih->daddr)), bswap(th->source), bswap(th->dest));
    }
    """

    lwcb = pylwcb.Pylwcb(lwcb_program)
    lwcb.attach()

    events = lwcb.read_events()
    for event in events:
        print(event)


- ``lwcb_program`` 存放了 lwcb 脚本代码，其主要功能是探测内核的 tcp_rcv_established 函数，打印 tcp 接收到
    报文的四元组，即源地址、目的地址、源端口和目的端口。

- ``lwcb = pylwcb.Pylwcb(lwcb_program)`` 创建了 Pylwcb 实例

- ``lwcb.attach()`` 编译并加载 eBPF 程序 

- ``lwcb.read_events()`` 读取 eBPF 程序的输出

