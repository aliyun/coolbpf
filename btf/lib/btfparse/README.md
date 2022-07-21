



## btfparse

专用于解析btf文件，目前支持以下功能：

1. 根据结构体的名字和成员的名字确定成员在该结构体内的偏移，以及成员的大小。


### 编译

1. 运行命令 `mkdir build & cd build` 创建编译目录

2. 运行命令 `cmake ..` 生成 Makefile 文件

3. 运行命令 `make btfparse btfparsetest`

4. 运行测试程序: `./btf/lib/btfparse/btfparsetest`
