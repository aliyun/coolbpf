

LightWeight CoolBPF building guide
==================================


1. 编译准备工作
------------------

- 安装 rust 编译工具链：``curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh``

- 克隆 coolbpf 代码：``git clone https://gitee.com/anolis/coolbpf.git``

- 进入到 lwcb 目录：``cd coolbpf/lwcb``

2. 编译 
------------------

``cargo build --release`` 即可完成编译，生成的 lwcb 可执行程序在：``target/release/lwcb``。