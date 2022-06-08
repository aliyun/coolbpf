如何生成对应的vmlinux.h
    0. pahole: git://git.kernel.org/pub/scm/devel/pahole/pahole.git
       bptftool: linux 最新: toosl/bpf/bpftool
    1. 安装对应内核 kernel-debuginfo RPM，获得包含 DWARF 的 vmlinux
    2. DWARF 生成 BTF section：pahole -J vmlinux
    3. 导出 BTF 字段并生成 headers: bpftool btf dump file vmlinux format c > vmlinux.h
