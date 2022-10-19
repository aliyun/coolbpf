# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     replaceHead
   Description :
   Author :       liaozhaoyan
   date：          2022/6/22
-------------------------------------------------
   Change Activity:
                   2022/6/22:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys


def rep(fList):
    lbc, vmlinux, dst = fList
    with open(vmlinux, "r") as fVmlinux:
        with open(lbc, "r") as fLbc:
            strVmlinux = fVmlinux.read()
            strLbc = fLbc.read()

            if "BPF_ANY " in strVmlinux:
                strLbc = strLbc.replace("ENUM_DEFINE_BPF_ANY", "")
            else:
                strLbc = strLbc.replace("ENUM_DEFINE_BPF_ANY",
                                        """enum {
    BPF_ANY = 0,
    BPF_NOEXIST = 1,
    BPF_EXIST = 2,
    BPF_F_LOCK = 4,
};""")
            if "BPF_F_FAST_STACK_CMP " in strVmlinux:
                strLbc = strLbc.replace("ENUM_DEFINE_STACK_CMP", "")
            else:
                strLbc = strLbc.replace("ENUM_DEFINE_STACK_CMP",
                                        """enum {
    BPF_F_SKIP_FIELD_MASK = 255,
    BPF_F_USER_STACK = 256,
    BPF_F_FAST_STACK_CMP = 512,
    BPF_F_REUSE_STACKID = 1024,
    BPF_F_USER_BUILD_ID = 2048,
};""")
            with open(dst, "w") as f:
                f.write(strLbc)


if __name__ == "__main__":
    rep(sys.argv[1:])
    pass
