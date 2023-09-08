# 第二章：eBPF 技术介绍

## 2.1 eBPF架构

## 2.2 eBPF加载过程
从代码到可执行程序，包括编译字节码，解析，map创建，程序加载，关联与挂载

## 2.3 eBPF常见程序类型
常见的主要介绍一下：xdp、tc、sockops、LSM、kprobe
包括：功能，目标、场景

## 2.4 map的实现和作用
Map的原理和作用
多种map的区别和适用场景

## 2.5 eBPF常见的开发框架 
    bcc、bpftrace、libbpf、cilium-eBPF、eunomia、coolbpf、
   （王传国整理，媛姐/吉旺提供一些资料）
对各框架进行简单介绍，龙蜥会着重描述coolbpf


### 2.5.1 coolbpf 开发框架

coolbpf 项目，以CORE（Compile Once--Run Everywhere）为基础实现，保留了资源占用低、可移植性强等优点，还融合了BCC动态编译的特性，适合在生产环境批量部署应用。Coolbpf 分为三大组件开发&测试、编译组件和基础模块。开发&测试组件提供了多语言开发和自动化测试功能；编译组件提供了多种编译方式，灵活性高；基础模块提供了BTF、低版本内核eBPF驱动、通用库等多个功能。

![coolbpf 架构图](../images/coolbpf-framework.png)


* 开发测试模块

目前coolbpf项目支持python、rust、go及c语言，覆盖了当前主流的高级开发语言。此外 coolbpf 还支持 lwcb 脚本语言，便于开发者快速开发eBPF功能脚本。

Generic library：基础通用库，提供了eBPF相关的API，如eBPF map、eBPF program等；

Language bindings：基础通用库的bindings，使得多种编程语言能够直接使用基础通用库；

Language library：由于 bindings缺少高级语言的面向对象编程思想，为此在language bindings的基础上做进一步的封装。


![开发&测试模块架构图](../images/coolbpf-dev-fw.png)

* 编译模块

本地编译服务，基础库封装，客户使用本地容器镜像编译程序，调用封装的通用函数库简化程序编写和数据处理；本地编译服务，不需要推送bpf.c到远程，但是一些常用的库和工具，通过我们提供的镜像就已经包含在里面，省去了构建环境的繁杂。

远程编译服务，接收bpf.c，生成bpf.so或bpf.o，提供给高级语言进行加载，用户只专注自己的功能开发，不用关心底层库安装、环境搭建；远程编译服务，目前用户开发代码时只需要pip install coolbpf，程序就会自动到我们的编译服务器进行编译。

脚本语言编译主要功能是编译lwcb脚本，生成eBPF字节码。

![编译组件架构图](../images/coolbpf-compile-fw.png)



* 基础模块

基础模块提供了关键组件。coolbpf 为了保证 eBPF 程序能够运行在低版本内核，提供了coolbpf 库和 eBPF 驱动。其中coolbpf 库用于发起 eBPF 程序运行时的系统调用或向 eBPF 驱动发起的 ioctl 请求。eBPF 驱动则根据 ioctl 请求的具体信息执行相应的动作，如创建 map，prog 的安全检查、JIT 等。

![基础模块架构图](../images/coolbpf-base-fw.png)


<footer>
<span class="copyright">Copyright © openanolis.cn 2023 all right reserved</span>

<pre><code class="footer-code">作者: OpenAnolis
链接: https://gitee.com/anolis/coolbpf/tree/master/docs/white-book
来源: OpenAnolis
本文原创发布于「OpenAnolis」,转载请注明出处,谢谢合作!
</code></pre>
</footer>
