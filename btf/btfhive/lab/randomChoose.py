# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     randomChoose
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

class workProc(Process):
    def __init__(self, index):
        super(workProc, self).__init__()
        self._index = index

    def run(self):
        print(f"pid {os.getpid()}, {self._index}")
        time.sleep(self._index / 10)

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

if __name__ == "__main__":
    L = list(range(20))
    shuffle(L)
    ts = []
    for i in range(4):
        ts.append(dispathThread(L))
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    pass
