



### 编译流程

#### ebpf 驱动编译流程

1. 安装目标内核版本的 kernel-devel 包，以 3.10.0-327.ali2017.alios7.x86_64 为例： `yum install kernel-devel-3.10.0-327.ali2017.alios7.x86_64`

2. 配置编译环境和安装编译工具：

```shell
yum install cmake
yum install elfutils-devel.x86_64
yum install zlib-devel.x86_64
```

3. 运行命令 `mkdir build & cd build` 创建编译目录，build目录建立在coolbpf项目根目录

4. 运行命令 `cmake ..` 生成 Makefile 文件

5. 运行命令 `make ebpfdrv KERNEL_VERSION=3.10.0-327.ali2017.alios7.x86_64`

6. 生成的驱动所在路径 `lcc/glcc/lib/ebpf/ebpfdrv.ko`


### 运行流程

1. 安装驱动: `insmod ebpfdrv.ko`

2. 使能驱动: `export ENABLE_BPF_DRV=1`

3. 运行程序: `./YOUR_APPLICATION`
