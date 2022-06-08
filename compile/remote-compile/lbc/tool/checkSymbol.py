# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     checkSymbol
   Description :
   Author :       liaozhaoyan
   date：          2021/7/17
-------------------------------------------------
   Change Activity:
                   2021/7/17:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import re

class ClbcSymbol(object):
    def __init__(self):
        self.__reEvent = re.compile("LBC_PERF_OUTPUT[ \\t]*\\([ \\t]*[a-zA-Z0-9_]+[ \\t]*,[ \\t]*[a-zA-Z0-9_ ]+[ \\t]*,[ \\t]*[a-zA-Z0-9_]+[ \\t]*\\)[ \\t]*;")
        reHash = re.compile("LBC_HASH[ \\t]*\\([ \\t]*[a-zA-Z0-9_]+[ \\t]*,[ \\t]*[a-zA-Z0-9_ \\[\\]]+[ \\t]*,[ \\t]*[a-zA-Z0-9_ \\[\\]]+[ \\t]*,[ \\t]*[a-zA-Z0-9_]+[ \\t]*\\)[ \\t]*;")
        reArray = re.compile("LBC_ARRAY[ \\t]*\\([ \\t]*[a-zA-Z0-9_]+[ \\t]*,[ \\t]*[a-zA-Z0-9_ \\[\\]]+[ \\t]*,[ \\t]*[a-zA-Z0-9_ \\[\\]]+[ \\t]*,[ \\t]*[a-zA-Z0-9_]+[ \\t]*\\)[ \\t]*;")
        reLruHash = re.compile(
            "LBC_LRU_HASH[ \\t]*\\([ \\t]*[a-zA-Z0-9_]+[ \\t]*,[ \\t]*[a-zA-Z0-9_ \\[\\]]+[ \\t]*,[ \\t]*[a-zA-Z0-9_ \\[\\]]+[ \\t]*,[ \\t]*[a-zA-Z0-9_]+[ \\t]*\\)[ \\t]*;")
        rePerHash = re.compile(
            "LBC_PERCPU_HASH[ \\t]*\\([ \\t]*[a-zA-Z0-9_]+[ \\t]*,[ \\t]*[a-zA-Z0-9_ \\[\\]]+[ \\t]*,[ \\t]*[a-zA-Z0-9_ \\[\\]]+[ \\t]*,[ \\t]*[a-zA-Z0-9_]+[ \\t]*\\)[ \\t]*;")
        rePerArray = re.compile(
            "LBC_PERCPU_Array[ \\t]*\\([ \\t]*[a-zA-Z0-9_]+[ \\t]*,[ \\t]*[a-zA-Z0-9_ \\[\\]]+[ \\t]*,[ \\t]*[a-zA-Z0-9_ \\[\\]]+[ \\t]*,[ \\t]*[a-zA-Z0-9_]+[ \\t]*\\)[ \\t]*;")
        reLruPerHash = re.compile(
            "LBC_LRU_PERCPU_HASH[ \\t]*\\([ \\t]*[a-zA-Z0-9_]+[ \\t]*,[ \\t]*[a-zA-Z0-9_ \\[\\]]+[ \\t]*,[ \\t]*[a-zA-Z0-9_ \\[\\]]+[ \\t]*,[ \\t]*[a-zA-Z0-9_]+[ \\t]*\\)[ \\t]*;")
        reStack = re.compile(
            "LBC_STACK[ \\t]*\\([ \\t]*[a-zA-Z0-9_]+[ \\t]*,[ \\t]*[a-zA-Z0-9_]+[ \\t]*\\)[ \\t]*;")
        self._reMaps = {
            'hash': reHash,
            'array': reArray,
            'lruHash': reLruHash,
            'perHash': rePerHash,
            'perArray': rePerArray,
            'lruPerHash': reLruPerHash,
            'stack': reStack,
        }

        self.__reInBrackets = re.compile("(?<=\\().+?(?=\\))")

    def findEvent(self, s):
        ds = {}
        es = self.__reEvent.findall(s)
        for e in es:
            l = self.__reInBrackets.findall(e)[0]
            m, t, other = l.split(",", 2)
            ds[m.strip()] = {'type': 'event', "ktype": None, "vtype": t.strip()}
        return ds

    def findMaps(self, s):
        ds = {}
        for t, reMap in self._reMaps.items():
            es = reMap.findall(s)
            if t == 'stack':
                for e in es:
                    l = self.__reInBrackets.findall(e)[0]
                    m, other = l.split(",", 1)
                    ds[m.strip()] = {'type': t, "ktype": 'u32', "vtype": 'u64[127]'}
            else:
                for e in es:
                    l = self.__reInBrackets.findall(e)[0]
                    m, k, v, other = l.split(",", 3)
                    ds[m.strip()] = {'type': t, "ktype": k.strip(), "vtype": v.strip()}
        return ds

if __name__ == "__main__":
    sym = ClbcSymbol()
    with open('/Users/liaozhaoyan/work/sh/c/lbc/bpf/lbc.bpf.c') as f:
        s = f.read()
        print(sym.findEvent(s))
