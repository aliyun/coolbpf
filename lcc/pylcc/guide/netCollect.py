# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     netCollect.py
   Description :
   Author :       liaozhaoyan
   date：          2021/8/5
-------------------------------------------------
   Change Activity:
                   2021/8/5:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import sys

import time
import ctypes as ct
import socket
import struct
from threading import Thread
if sys.version_info.major >= 3:
    from queue import Queue, Full
else:
    from Queue import Queue, Full

from pylcc.lbcBase import ClbcBase
from common.cmds import CconProc

typeList = ["rto_retrans", "zero_probe", "noport_reset", "bad_sync", "net_proc", "syn_send", "syn_ack"]
resetList = ['noport', 'bad_ack', "bad_syn", "tw_rst", "tcp_stat", "tcp_oom", "keep_alive", "bad_close", "disconnect", "tcp_abort"]


class CPushThread(Thread):
    def __init__(self, q, qName, sender):
        super(CPushThread, self).__init__()
        self.setDaemon(True)
        self._q = q
        self._name = qName
        self._send = sender

    def run(self):
        count = 0
        i = 0
        while True:
            logs = ""
            while not self._q.empty():
                log = self._q.get()
                logs += log.replace('"', '\\"') + "; "
                count += 1
            if len(logs):
                self._send.put(self._name, ',level=warn log="%s"' % (logs[:-2]))
            i += 1
            if i >= 60:
                self._send.put(self._name + '_c', ' count=%d' % (count))
                i = 0
                count = 0
            time.sleep(1)


class CnetCollect(ClbcBase):
    def __init__(self, soPath, sender):
        super(CnetCollect, self).__init__(soPath, workPath=os.path.split(os.path.realpath(__file__))[0])
        self._send = sender
        self.__retransQ = Queue()
        self.__retransQ.maxsize = 5
        self.__resetQ = Queue()
        self.__resetQ.maxsize = 5
        self.__synRetransQ = Queue()
        self.__synRetransQ.maxsize = 5
        self._cp = CconProc()

        retransThread = CPushThread(self.__retransQ, 'net_retrans', sender)
        resetThread = CPushThread(self.__resetQ, 'net_reset', sender)
        synRetransThread = CPushThread(self.__synRetransQ, 'syn_retrans', sender)

        retransThread.start()
        resetThread.start()
        synRetransThread.start()

    def transPort(self, v):
        return struct.unpack('H', struct.pack('>H', v))[0]

    def transIp(self, v):
        return socket.inet_ntoa(struct.pack('>I', socket.htonl(v)))

    def sendLog(self, q, log):
        try:
            q.put(log, block=False)
        except Full:
            pass

    def dispatchReset(self, e, log):
        q = self.__resetQ
        if e.type == 2: #noport
            log += "noport"
            self.sendLog(q, log)
            return
        try:
            stacks = self.maps['callStack'].getStacks(e.stack_id, 2)
        except TypeError:
            # print("bad type.")
            return

        if e.type == 3:
            if stacks[1] == 'tcp_v4_rcv':
                if e.sk_state == 12: #TCP_NEW_SYN_RECV
                    stat = "bad_ack"
                else:
                    stat = "tw_rst"
            elif stacks[1] == 'tcp_check_req':
                stat = "bad_syn"
            elif stacks[1] == 'tcp_v4_do_rcv':
                stat = "tcp_stat"
            else:
                stat = 'unkown3%s' % stacks[1]
        elif e.type == 4:
            if stacks[1] == 'tcp_out_of_resources':
                stat = 'tcp_oom'
            elif stacks[1] == 'tcp_keepalive_timer':
                stat = 'keep_alive'
            elif stacks[1] == 'inet_release' or stacks[1] == 'tcp_close':
                stat = 'bad_close'
            elif stacks[1] == 'tcp_disconnect':
                stat = 'tcp_abort'
            elif stacks[1] == 'tcp_abort':
                stat = 'tcp_abort'
            else:
                stat = 'unkown4%s' % stacks[1]
        else:
            stat = 'bad%d' % e.type
        log += stat
        self.sendLog(q, log)

    def _packLog(self, e):
        log = "rcv_nxt:%d, rcv_wup:%d, snd_nxt:%d, snd_una:%d, copied_seq:%d, snd_wnd:%d, rcv_wnd:%d, lost_out:%d, packets_out:%d, retrans_out:%d, sacked_out:%d, reordering:%d, " % ( e.rcv_nxt, e.rcv_wup, e.snd_nxt, e.snd_una, e.copied_seq, e.snd_wnd, e.rcv_wnd, e.lost_out, e.packets_out, e.retrans_out, e.sacked_out, e.reordering)
        log += typeList[e.type]
        return log

    def _callback(self, cpu, data, size):
        stream = ct.string_at(data, size)
        e = self.maps['net_map'].event(stream)
        con = self._cp.getDockerName(e.con)
        log = 'con:%s, task:%d|%s, tcp:%s:%d->%s:%d, state:%d, ' % (con, e.pid, e.comm, self.transIp(e.ip_src), self.transPort(e.sport), self.transIp(e.ip_dst), self.transPort(e.dport), e.sk_state)

        if e.type < 2:
            log += self._packLog(e)
            self.sendLog(self.__retransQ, log)
        elif e.type >= 5:
            log += self._packLog(e)
            self.sendLog(self.__synRetransQ, log)
        else:
            self.dispatchReset(e, log)

    def loop(self):
        self.maps['net_map'].open_perf_buffer(self._callback)
        self.maps['net_map'].perf_buffer_poll()


def netCLoop(sender, version):
    if "3.10" in version:
        r = CnetCollect('netcollect.3.10', sender)
    else:
        r = CnetCollect('netcollect.4.plus', sender)
    r.loop()


if __name__ == "__main__":
    n = CnetCollect('netcollect.4.plus')
    n.loop()
