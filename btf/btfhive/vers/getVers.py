# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     getVers
   Description :
   Author :       liaozhaoyan
   date：          2022/1/11
-------------------------------------------------
   Change Activity:
                   2022/1/11:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'
import os

Dir = "../version/"
vD = {"x86_64": "../db/x86_64/", "aarch64":  "../db/aarch64/"}

def procVers(arch, path):
    files = os.listdir(path)
    files.sort()
    with open(os.path.join(Dir, arch + ".txt"), "w") as f:
        for name in files:
            if name.startswith("info-"):
                name = name.replace("info-", "")
                name = name.replace(".db", "")
                f.write(name + "\n")

if __name__ == "__main__":
    path = os.path.split(os.path.realpath(__file__))[0]
    os.chdir(path)
    for k, v in vD.items():
        procVers(k, v)
