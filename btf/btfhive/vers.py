# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     vers.py
   Description :
   Author :       liaozhaoyan
   date：          2022/1/20
-------------------------------------------------
   Change Activity:
                   2022/1/20:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

aliosUrl_x86_64 = "http://yum.tbsite.net/taobao/7/x86_64/current/kernel-debuginfo/"
aliosStableUrl_x86_64 = "http://yum.tbsite.net/taobao/7/x86_64/stable/kernel-debuginfo/"
centos7Url_x86_64 = "http://debuginfo.centos.org/7/x86_64/"
centos8Url_x86_64 = "http://debuginfo.centos.org/8/x86_64/Packages/"
centosSteamUrl_x86_64 = "http://debuginfo.centos.org/8-stream/x86_64/Packages/"
alinux219Url_x86_64 = "http://mirrors.aliyun.com/alinux/2.1903/plus/x86_64/debug/"
alinux2Url_x86_64 = "http://mirrors.aliyun.com/alinux/2/kernels/x86_64/debug/"
alinux3Url_x86_64 = "http://mirrors.aliyun.com/alinux/3/plus/x86_64/debug/"
ubuntuUrl_x86_64 = "http://ddebs.ubuntu.com/pool/main/l/linux/"
anolis8x4Url_x86_64 = "http://mirrors.aliyun.com/anolis/8.4/BaseOS/x86_64/debug/Packages/"
anolis8x2Url_x86_64 = "http://mirrors.aliyun.com/anolis/8.2/BaseOS/x86_64/debug/Packages/"
anolis8Url_x86_64 = "http://mirrors.aliyun.com/anolis/8/BaseOS/x86_64/debug/Packages/"
anolis7Url_x86_64 = "http://mirrors.aliyun.com/anolis/7.7/os/x86_64/debug/Packages/"
anolis8x4Url1_x86_64 = "http://mirrors.openanolis.cn/anolis/8.4/Plus/x86_64/debug/Packages/"
anolis8x2Url1_x86_64 = "http://mirrors.openanolis.cn/anolis/8.2/Plus/x86_64/debug/Packages/"
anolis8Url1_x86_64 = "http://mirrors.openanolis.cn/anolis/8/Plus/x86_64/debug/Packages/"
anolis7Url1_x86_64 = "http://mirrors.openanolis.cn/anolis/7.7/Plus/x86_64/debug/Packages/"
anolis7X9Url1_x86_64 = "http://mirrors.openanolis.cn/anolis/7.9/Plus/x86_64/debug/Packages/"

x86_64_D = {
    "alios": [aliosUrl_x86_64, aliosStableUrl_x86_64],
    "alinux": [alinux2Url_x86_64, alinux219Url_x86_64, alinux3Url_x86_64],
    "anolis": [anolis7Url_x86_64, anolis8Url_x86_64, anolis8x2Url_x86_64, anolis8x4Url_x86_64,
               anolis7Url1_x86_64, anolis7X9Url1_x86_64, anolis8Url1_x86_64, anolis8x2Url1_x86_64, anolis8x4Url1_x86_64],
    "ubuntu": [ubuntuUrl_x86_64],
    "centos": [centos7Url_x86_64, centos8Url_x86_64, centosSteamUrl_x86_64],
}

aliosUrl_aarch64 = "http://yum.tbsite.net/taobao/7/aarch64/current/kernel-debuginfo/"
aliosStableUrl_aarch64 = "http://yum.tbsite.net/taobao/7/aarch64/stable/kernel-debuginfo/"
centos7Url_aarch64 = "http://debuginfo.centos.org/7/aarch64/"
centos8Url_aarch64 = "http://debuginfo.centos.org/8/aarch64/Packages/"
centosStreamUrl_aarch64 = "http://debuginfo.centos.org/8-stream/aarch64/Packages/"
alinux219Url_aarch64 = "http://mirrors.aliyun.com/alinux/2.1903/plus/aarch64/debug/"
alinux2Url_aarch64 = "http://mirrors.aliyun.com/alinux/2/kernels/aarch64/debug/"
alinux3Url_aarch64 = "http://mirrors.aliyun.com/alinux/3/plus/aarch64/debug/"
ubuntuUrl_aarch64 = "http://ddebs.ubuntu.com/pool/main/l/linux/"
anolis8x4Url_aarch64 = "http://mirrors.aliyun.com/anolis/8.4/BaseOS/aarch64/debug/Packages/"
anolis8x2Url_aarch64 = "http://mirrors.aliyun.com/anolis/8.2/BaseOS/aarch64/debug/Packages/"
anolis8Url_aarch64 = "http://mirrors.aliyun.com/anolis/8/BaseOS/aarch64/debug/Packages/"
anolis7Url_aarch64 = "http://mirrors.aliyun.com/anolis/7.7/os/aarch64/debug/Packages/"
anolis8x4Url1_aarch64 = "http://mirrors.openanolis.cn/anolis/8.4/Plus/aarch64/debug/Packages/"
anolis8x2Url1_aarch64 = "http://mirrors.openanolis.cn/anolis/8.2/Plus/aarch64/debug/Packages/"
anolis8Url1_aarch64 = "http://mirrors.openanolis.cn/anolis/8/Plus/aarch64/debug/Packages/"
anolis7Url1_aarch64 = "http://mirrors.openanolis.cn/anolis/7.7/Plus/aarch64/debug/Packages/"
anolis7X9Url1_aarch64 = "http://mirrors.openanolis.cn/anolis/7.9/Plus/aarch64/debug/Packages/"

aarch64_D = {
    "alios": [aliosUrl_aarch64, aliosStableUrl_aarch64],
    "alinux": [alinux2Url_aarch64, alinux219Url_aarch64, alinux3Url_aarch64],
    "anolis": [anolis7Url_aarch64, anolis8Url_aarch64, anolis8x2Url_aarch64, anolis8x4Url_aarch64,
               anolis7Url1_aarch64, anolis7X9Url1_aarch64, anolis8Url1_aarch64, anolis8x2Url1_aarch64, anolis8x4Url1_aarch64],
    "ubuntu": [ubuntuUrl_aarch64],
    "centos": [centos7Url_aarch64, centos8Url_aarch64, centosStreamUrl_aarch64],
}

versD = {"x86_64": x86_64_D, "aarch64": aarch64_D}

if __name__ == "__main__":
    pass
