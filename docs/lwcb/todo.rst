

LightWeight CoolBPF todo features
=================================

虽然 lwcb 已经能够初步运行，但是仍存在一些不足之处，需要通过增加新的特性来完善它：

1. 支持 tracepoint 探测类型，其主要工作主要有：
    * 解析 ``/sys/kernel/debug/tracing/events/<category>/<name>/format`` 数据格式
    * 提供参数入参解析
    * 实现 ``TracepointProgram`` ，完成 ``load、attach`` 等操作

2. 支持 ``array map`` 类型，具体实现可以参考 ``hash map`` 类型的实现： ``lwcb/src/bpf/map/hash.rs`` 

3. 支持 ``uprobe`` 探测类型

4. 支持 ``begin、end`` 探测类型

5. 完善编译错误信息

6. 支持 ``tuple``

7. 支持 ``for`` 循环及循环展开

8. 支持 ``btf id``， 由于 ``btf id`` 是高内核版本才支持的，所以需要动态检测判断是否开启 ``btf id``

