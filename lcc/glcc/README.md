




### 编译流程

#### ebpf 驱动编译流程

1. 安装目标内核版本的 kernel-devel 包，以 3.10.0-327.ali2017.alios7.x86_64 为例： `yum install kernel-devel-3.10.0-327.ali2017.alios7.x86_64`

2. 运行命令 `mkdir build & cd build` 创建编译目录

3. 运行命令 `cmake ..` 生成 Makefile 文件

4. 运行命令 `make ebpfdrv`

#### ringbuffer 驱动编译流程

1. 安装目标内核版本的 kernel-devel 包，以 3.10.0-327.ali2017.alios7.x86_64 为例： `yum install kernel-devel-3.10.0-327.ali2017.alios7.x86_64`

2. 运行命令 `mkdir build & cd build` 创建编译目录

3. 运行命令 `cmake ..` 生成 Makefile 文件

4. 运行命令 `make ringbuffer`

#### hook 库编译流程

1. 运行命令 `mkdir build & cd build` 创建编译目录

2. 运行命令 `cmake ..` 生成 Makefile 文件

3. 运行命令 `make hook`
