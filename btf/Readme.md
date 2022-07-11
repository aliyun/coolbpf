### 如何生成对应的vmlinux.h
0. pahole: git://git.kernel.org/pub/scm/devel/pahole/pahole.git  <br/>
   bptftool: linux 最新: tools/bpf/bpftool                   <br/>
1. 安装对应内核 kernel-debuginfo RPM，获得包含 DWARF 的 vmlinux   <br/>
2. DWARF 生成 BTF section：pahole -J vmlinux            <br/>
3. 导出 BTF 字段并生成 headers: bpftool btf dump file vmlinux format c > vmlinux.h  <br/>
