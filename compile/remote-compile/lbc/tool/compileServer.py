# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     compileServer
   Description :
   Author :       liaozhaoyan
   date：          2021/8/26
-------------------------------------------------
   Change Activity:
                   2021/8/26:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
import time
import signal
from socket import *
import json
import re
import os
import shlex
import base64
from subprocess import PIPE, Popen
from udpHook import udpPut
from multiprocessing import Process, Lock
import hashlib
from infoParse import CinfoParse

workDir = "/home/src/pylcc"
compileDir = workDir + "/lbc"
btfDir = workDir + "/hive/btf/"
dbDir = workDir + "/hive/db/"

soFile = "bpf.so"

LBC_COMPILE_PORT = 7654
# max 0xffffffff 4G
buffSize = 128 * 1024

class CexecCmd(object):
    def __init__(self):
        pass

    def cmd(self, cmds):
        p = Popen(shlex.split(cmds), stdout=PIPE, stderr=PIPE)
        return p.stdout.read().decode() + p.stderr.read().decode()

    def system(self, cmds):
        cmds = cmds.replace('\0', '').strip()
        return os.system(cmds)


class ClocalTcpServer(Process):
    def __init__(self, port):
        self._c = CexecCmd()
        self._callDict = {
            "c": self._compileSo,
            "btf": self._sendBtf,
            "func": self._getFunc,
            "struct": self._getStruct,
            "type": self._getType,
        }
        super(ClocalTcpServer, self).__init__()
        self._lock = Lock()
        self.server_socket = socket(AF_INET, SOCK_STREAM)
        self.server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, True)
        self.server_socket.bind(("0.0.0.0", port))
        self.server_socket.listen(10)
        self._reSql = re.compile(r"[^a-zA-Z0-9_% ]")

    def run(self):
        while True:
            client_socket, client_addr = self.server_socket.accept()
            tr = Process(target=self.recv_data, args=(client_socket, client_addr))
            tr.start()
            # tr.join()

    def _checkSql(self, sql):
        res = self._reSql.findall(sql)
        if len(res) == 0:
            return True
        return False

    def __parseVer(self, ver):
        major, minor, _ = ver.split(".", 2)
        return major + "+" + minor

    def _recv_lbc(self, s):
        try:
            d = s.recv(buffSize).decode()
        except UnicodeDecodeError:
            return None
        if d[:3] != "LBC":
            return None
        size = d[3:11]
        try:
            size = int(size, 16) + 11
        except:
            return None
        if size > buffSize:
            return None
        while len(d) < size:
            d += s.recv(buffSize)
        return json.loads(d[11:])

    def _send_lbc(self, s, send):
        send = "LBC%08x" % (len(send)) + send
        s.send(send.encode())

    def _setupArch(self, dRecv):
        if 'arch' in dRecv:
            return dRecv['arch']
        return 'x86_64'

    def _changeDbDir(self, dRecv):
        arch = self._setupArch(dRecv)
        dbPath = dbDir + f"{arch}/"
        if not os.path.exists(dbPath):
            return {"log": f"arch {arch} not support."}
        else:
            os.chdir(dbPath)
            return {"log": "ok."}

    def _dbCheck(self, dRecv, k):
        path = f"info-{dRecv['ver']}.db"
        try:
            i = CinfoParse(path)
        except IOError:
            return {"log": "version not support."}
        if k not in dRecv or dRecv[k] == "" or not self._checkSql(dRecv[k]):
            return {"log": f"bad {k} key."}
        return {"db": i}

    def _dbCheckArg(self, k, v):
        if ";" in v:
            return {"log": f"bad {k} key."}

    def __getFunc(self, dRecv):
        dSend = {"log": "ok."}
        ds = self._dbCheck(dRecv, "func")
        if "log" in ds:
            return ds
        i = ds["db"]
        func = dRecv["func"]
        if "ret" in dRecv:
            r = self._dbCheckArg("ret", dRecv["ret"])
            if r:
                return r
            try:
                dSend['res'] = i.getFuncFilterRet(dRecv["ret"], func=dRecv["func"])
                return dSend
            except ValueError:
                return {"log": f"query value error."}
        if "arg" in dRecv:
            r = self._dbCheckArg("arg", dRecv["arg"])
            if r: return r
            try:
                dSend['res'] = i.getFuncFilterArg(dRecv["arg"], func=dRecv["func"])
                return dSend
            except ValueError:
                return {"log": f"query value error."}
        if "%" in func:
            dSend['res'] = i.getFuncs(func)
        else:
            dSend['res'] = i.getFunc(func)
        return dSend

    def _getFunc(self, client_socket, dRecv):
        res = self._changeDbDir(dRecv)
        if res['log'] != "ok.":
            self._send_lbc(client_socket, json.dumps(res))
        res = self.__getFunc(dRecv)
        self._send_lbc(client_socket, json.dumps(res))

    def __getStuct(self, dRecv):
        dSend = {"log": "ok."}
        ds = self._dbCheck(dRecv, "struct")
        if "log" in ds:
            return ds
        i = ds["db"]
        struct = dRecv["struct"]
        dSend['res'] = i.getStruct(struct)
        return dSend

    def _getStruct(self, client_socket, dRecv):
        res = self._changeDbDir(dRecv)
        if res['log'] != "ok.":
            self._send_lbc(client_socket, json.dumps(res))
        self._send_lbc(client_socket, json.dumps(self.__getStuct(dRecv)))

    def __getType(self, dRecv):
        dSend = {"log": "ok."}
        ds = self._dbCheck(dRecv, "type")
        if "log" in ds:
            return ds
        i = ds["db"]
        t = dRecv["type"]
        dSend['res'] = i.getType(t)
        return dSend

    def _getType(self, client_socket, dRecv):
        res = self._changeDbDir(dRecv)
        if res['log'] != "ok.":
            self._send_lbc(client_socket, json.dumps(res))
        self._send_lbc(client_socket, json.dumps(self.__getType(dRecv)))

    def _transArch(self, arch):
        if arch == 'x86_64':
            return 'x86'
        return arch

    def _compileSo(self, client_socket, dRecv):
        dSend = {"log": "not start", "so": None}
        if "code" not in dRecv:
            self._send_lbc(client_socket, json.dumps({"log": "not code."}))
            return
        if 'env' not in dRecv:
            dRecv['env'] = ""
        with self._lock:
            print("compile for %s" % dRecv['ver'])
            os.chdir(compileDir)
            with open("bpf/lbc.bpf.c", 'w') as f:
                f.write(dRecv['code'])
            if os.path.exists(soFile):
                os.remove(soFile)
            ver = dRecv['ver']
            arch = self._setupArch(dRecv)
            self._c.cmd("rm -f bpf/vmlinux.h")
            dSend['log'] = self._c.cmd('make VMLINUX_VERSION=%s ARCH=%s CARCH=%s %s' % (ver,
                                                                                        arch,
                                                                                        self._transArch(arch),
                                                                                        dRecv['env']))
            print(dSend['log'])
            try:
                with open(soFile, 'rb') as f:
                    dSend['so'] = base64.b64encode(f.read()).decode()
            except:
                print("comiple fialed.")
        self._send_lbc(client_socket, json.dumps(dSend))

    def _sendBtf(self, client_socket, dRecv):
        arch = self._setupArch(dRecv)
        btfPath = btfDir + f"{arch}/"
        os.chdir(btfPath)
        dSend = {'ver': dRecv['ver'], 'arch': arch}
        name = "vmlinux-%s" % dRecv['ver']
        try:
            with open(name, 'rb') as f:
                dSend['btf'] = base64.b64encode(f.read()).decode()
                dSend['log'] = "get btf file ok."
        except IOError:
            dSend['log'] = "read btf file failed."
        self._send_lbc(client_socket, json.dumps(dSend))

    # data format: {"cmd": "btf/c/db/func/struct", "ver"}
    def _recv_data(self, client_socket):
        dRecv = self._recv_lbc(client_socket)
        if dRecv is None:
            return

        if "cmd" not in dRecv:
            dRecv['log'] = 'unknown request.'
            self._send_lbc(client_socket, json.dumps(dRecv))
            return

        if dRecv["cmd"] not in self._callDict:
            dRecv['log'] = 'unknown cmd.'
            self._send_lbc(client_socket, json.dumps(dRecv))
            return

        if "ver" not in dRecv:
            dRecv['log'] = 'no kernel version info.'
            self._send_lbc(client_socket, json.dumps(dRecv))
            return

        udpPut(dRecv)
        self._callDict[dRecv['cmd']](client_socket, dRecv)

    def recv_data(self, client_socket, client_addr):
        self._recv_data(client_socket)
        client_socket.close()


if __name__ == "__main__":
    server = ClocalTcpServer(LBC_COMPILE_PORT)
    server.start()
    try:
        signal.pause()
    except KeyboardInterrupt:
        print("stop")
        pid = os.getpid()
        os.system("kill %d" % pid)
