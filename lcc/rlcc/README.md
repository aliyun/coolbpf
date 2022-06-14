
### 编译 example 流程

1. `SKEL_RS=1 cargo build --release` 生成 rust skel 文件
2. `SKEL_RS=0 cargo build --release` 无需在生成 rust skel 文件

默认 SKEL_RS 为 1

### 编译 rexample 流程

rexample 使用了远程编译功能，具体编译流程如下


1. 运行命令 `mkdir build & cd build` 创建编译目录

2. 运行命令 `cmake ..` 生成 Makefile 文件

3. 运行命令 `make rexample`

4. 运行 example 程序: `../lcc/rlcc/rexample/target/release/rexample`