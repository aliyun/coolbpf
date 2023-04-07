





### 编译容器部署

1. 拉取编译容器：`docker pull registry.cn-hangzhou.aliyuncs.com/alinux/lcc:latest`

2. 启动编译容器：`docker run --name bpf-build -itd -v <PATH>:<PATH> --net host registry.cn-hangzhou.aliyuncs.com/alinux/lcc:latest /sbin/init`

注意：<PATH> 建议为coolbpf工作目录





