
### 编译 example 流程

1. `SKEL_RS=1 cargo build --release` 生成 rust skel 文件
2. `SKEL_RS=0 cargo build --release` 无需在生成 rust skel 文件

默认 SKEL_RS 为 1