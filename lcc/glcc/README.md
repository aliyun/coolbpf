



### 运行示例

运行命令是： `LD_PRELOAD=./lcc/glcc/lib/ebpf/libhook.so <BIN>`


`LD_PRELOAD` 优先加载 hook 库
`./lcc/glcc/lib/ebpf/libhook.so` 是 hook 库所在的位置
`<BIN>` 所要运行的程序

运行前先准备下 ebpfdrv 驱动和 hook 库，具体参考下面的编译流程。

### 编译流程

#### ebpf 驱动编译流程

1. 安装目标内核版本的 kernel-devel 包，以 3.10.0-327.ali2017.alios7.x86_64 为例： `yum install kernel-devel-3.10.0-327.ali2017.alios7.x86_64`

2. 运行命令 `mkdir build & cd build` 创建编译目录，build目录建立在coolbpf项目根目录

3. 运行命令 `cmake ..` 生成 Makefile 文件

4. 运行命令 `make ebpfdrv`

5. 安装驱动 `insmod lcc/glcc/lib/ebpf/ebpfdrv.ko`

#### ringbuffer 驱动编译流程

1. 安装目标内核版本的 kernel-devel 包，以 3.10.0-327.ali2017.alios7.x86_64 为例： `yum install kernel-devel-3.10.0-327.ali2017.alios7.x86_64`

2. 运行命令 `mkdir build & cd build` 创建编译目录，build目录建立在coolbpf项目根目录

3. 运行命令 `cmake ..` 生成 Makefile 文件

4. 运行命令 `make ringbuffer`

#### hook 库编译流程

1. 运行命令 `mkdir build & cd build` 创建编译目录，build目录建立在coolbpf项目根目录

2. 运行命令 `cmake ..` 生成 Makefile 文件

3. 运行命令 `make hook`

