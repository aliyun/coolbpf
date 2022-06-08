# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     multiSpider
   Description :
   Author :       liaozhaoyan
   date：          2022/1/21
-------------------------------------------------
   Change Activity:
                   2022/1/21:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import time
from random import shuffle
from multiprocessing import Process
from threading import Thread
from spider import Cspider
from getVmlinux import CgetVmlinux
import traceback

class workProc(Process):
    def __init__(self, res):
        super(workProc, self).__init__()
        self._res = res

    def run(self):
        vm = CgetVmlinux()
        try:
            vm.proc(*self._res)
        except Exception as e:
            print(f"except msg: {e}")
            traceback.print_exc()

    def work(self):
        self.start()
        self.join()

class dispathThread(Thread):
    def __init__(self, L):
        super(dispathThread, self).__init__()
        self._L = L

    def run(self):
        while True:
            try:
                cell = self._L.pop()
            except IndexError:
                return
            w = workProc(cell)
            w.work()

class CmultiSpider(Cspider):
    def __init__(self):
        super(CmultiSpider, self).__init__()
        self._L = []

    def _proc(self, url, href, release, arch):
        print(f"append {arch}, {href}")
        self._L.append([url, href, release, arch])

    def work(self):
        super(CmultiSpider, self).work()
        shuffle(self._L)
        ts = []
        print("start to dispatch")
        for i in range(8):
            ts.append(dispathThread(self._L))
        for t in ts:
            t.start()
        for t in ts:
            t.join()

if __name__ == "__main__":
    s = CmultiSpider()
    s.work()
    pass
