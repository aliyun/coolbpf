



pylwcb developing guide
=======================

如果你想要开发 pylwcb 的更多功能，可以参考如下步骤去搭建开发环境、编译 pylwcb 和运行 pylwcb。


1. 开发环境搭建
------------------------

首先，我们需要搭建 pylwcb 的开发环境，主要有以下几个步骤：

1. 创建独立的 python 开发虚拟环境： ``python -m venv .env``

2. 激活该开发虚拟环境： ``source .env/bin/activate``

3. 安装 pylwcb 开发环境依赖的 python 库
    - ``pip install tomli``
    - ``pip install setuptools_rust``
    - ``pip install maturin``

至此，我们已经搭建好了 pylwcb 的开发环境。


2. 编译 pylwcb 
------------------------

我们可以通过命令：``maturin develop`` 来编译 pylwcb，进而生产相应的 python 模块。一般生成的
python 模块所在目录是：``.env/lib64/python3.6/site-packages/``

**注意：一般建议使用 pylwcb 提供的 devbuild.sh 脚本来编译。**


3. 使用 pylwcb 
------------------------

在第 2 步，我们生成了 pylwcb 的 python 模块，下面将介绍如何使用生成的 python 模块。 

.. code-block:: shell

    $ ./devbuild.sh 
    $ python
    >>> import pylwcb
    >>> pylwcb.say_hello()
    'hello from pylwcb modules'

4. 调试 pylwcb 
------------------------

在开发过程中，可能会遇到各种各样的 BUG，特别是 python 截取了 rust 程序的输出，导致无法在终端
查看 rust 产生的各种日志。

如果遇到程序 crash，我们可以通过如下命令查看 crash 时的堆栈：

- 执行你的 python 脚本：``rust-gdb --args python test.py``

- 按下 r 键盘，让程序跑起来：``r``

- 输入 ``bt`` 即可显示 crash 时的堆栈 

参考：`pyo3 debugging guide <https://pyo3.rs/v0.18.1/debugging>`_ 

