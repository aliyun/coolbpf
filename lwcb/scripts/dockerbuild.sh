#!/bin/sh

# do cargo clean
# THIS FILE WORKS WITH RTRACE
# prepare your docker environment
# step 1. docker pull registry.cn-hangzhou.aliyuncs.com/alinux/lcc:latest
# step 2. docker run --name bpf-build -itd -v $HOME:$HOME --net host registry.cn-hangzhou.aliyuncs.com/alinux/lcc:latest /sbin/init
# step 3. docker exec -it bpf-build /bin/bash
# step 4. curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# step 5. yum install gcc

cargo clean
workpath=`pwd`
# docker exec -it bpf-build sh -c  "cd $workpath && source \"$HOME/.cargo/env\" && cargo build --release --features libbpf-rs/novendor && \cp $workpath/target/release/rtrace $workpath"
docker exec -it bpf-build sh -c  "cd $workpath && source \"$HOME/.cargo/env\" && cargo clean && cargo build --release && \cp $workpath/target/release/lwbt $workpath"