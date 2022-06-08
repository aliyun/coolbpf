# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     stripHead
   Description :
   Author :       liaozhaoyan
   date：          2022/1/18
-------------------------------------------------
   Change Activity:
                   2022/1/18:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'
import re

reStrip = re.compile("___[\d]+")
def transLines(lines):
    if lines[0].startswith("struct"):
        res = reStrip.search(lines[0])
        if res is not None:
            return ""
    nlines = [reStrip.sub("", lines[0])]
    for i, line in enumerate(lines[1:]):
        if line != "\n":
            nlines.append(reStrip.sub("", line))
    if len(nlines) == 1 and nlines[0] == "\n":
        return ""
    return "".join(nlines)

def stripHead(path):
    content = ""
    with open(path, 'r') as f:
        lines = []
        brackets = 0
        for i, line in enumerate(f):
            brackets += line.count("{")
            brackets -= line.count("}")
            lines.append(line)
            if brackets == 0:
                content += transLines(lines)
                lines = []

    with open("new.h", 'w') as f:
        f.write(content)

if __name__ == "__main__":
    stripHead("vmlinux-3.10.0-327.ali2019.alios7.x86_64.h")
