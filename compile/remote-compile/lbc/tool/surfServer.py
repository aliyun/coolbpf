# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     surfServer
   Description :
   Author :       liaozhaoyan
   date：          2022/5/9
-------------------------------------------------
   Change Activity:
                   2022/5/9:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import re
import base64
from subprocess import PIPE, Popen
import shlex
from udpHook import udpPut
from infoParse import CinfoParse
from getFuncs import CgenfuncsDb

rootDir = "/home"
dbDir = os.path.join(rootDir, "hive/db")
btfDir = os.path.join(rootDir, "hive/btf")
compileDir = os.path.join(rootDir, "lbc")
koBuildDir = os.path.join(rootDir, "lbc/ko")
soFile = "bpf.so"
dfFile = "pre.db"

SEG_UNIT = 4096


def segDecode(stream):
    line = b""
    l = len(stream)
    for i in range(0, l, 4 * SEG_UNIT):
        s = stream[i:i + 4 * SEG_UNIT]
        line += base64.b64decode(s)
    if l % (4 * SEG_UNIT):
        i = int(l / (4 * SEG_UNIT) * (4 * SEG_UNIT))
        line += base64.b64decode(stream[i:])
    return line


def segEncode(stream):
    line = b""
    l = len(stream)
    for i in range(0, l, 3 * SEG_UNIT):
        s = stream[i:i+3 * SEG_UNIT]
        line += base64.b64encode(s)
    if l % (3 * SEG_UNIT):
        i = int(l / (3 * SEG_UNIT) * (3 * SEG_UNIT))
        line += base64.b64encode(stream[i:])
    return line


class CexecCmd(object):
    def __init__(self):
        pass

    def cmd(self, cmds):
        p = Popen(shlex.split(cmds), stdout=PIPE, stderr=PIPE)
        return p.stdout.read().decode() + p.stderr.read().decode()

    def system(self, cmds):
        cmds = cmds.replace('\0', '').strip()
        return os.system(cmds)


class CsurfServer(object):
    def __init__(self, lock, udpHost):
        self._callDict = {
            "btf": self._sendBtf,
            "func": self._getFunc,
            "struct": self._getStruct,
            "type": self._getType,
            "c": self._compileSo,
            "ko": self._koBuild,
        }
        self._reSql = re.compile(r"[^a-zA-Z0-9_% ]")
        self._lock = lock
        self._c = CexecCmd()
        self._udpHost = udpHost

    def _checkSql(self, sql):
        res = self._reSql.findall(sql)
        if len(res) == 0:
            return True
        return False

    def _setupArch(self, dRecv):
        if 'arch' in dRecv:
            return dRecv['arch']
        return 'x86_64'

    def _changeDbDir(self, dRecv):
        arch = self._setupArch(dRecv)
        dbPath = os.path.join(dbDir, arch)
        if not os.path.exists(dbPath):
            return {"log": f"arch {arch} not support."}
        else:
            os.chdir(dbPath)
            return {"log": "ok."}

    def _changeKoDir(self):
        if not os.path.exists(koBuildDir):
            return {"log": f"arch not support."}
        else:
            os.chdir(koBuildDir)
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

    def _getType(self, dRecv):
        res = self._changeDbDir(dRecv)
        if res['log'] != "ok.":
            return res
        dSend = {"log": "ok."}
        ds = self._dbCheck(dRecv, "type")
        if "log" in ds:
            return ds
        i = ds["db"]
        t = dRecv["type"]
        dSend['res'] = i.getType(t)
        return dSend

    def _getStruct(self, dRecv):
        res = self._changeDbDir(dRecv)
        if res['log'] != "ok.":
            return res
        dSend = {"log": "ok."}
        ds = self._dbCheck(dRecv, "struct")
        if "log" in ds:
            return ds
        i = ds["db"]
        t = dRecv["struct"]
        dSend['res'] = i.getStruct(t)
        return dSend

    def _getFunc(self, dRecv):
        res = self._changeDbDir(dRecv)
        if res['log'] != "ok.":
            return res
        dSend = {"log": "ok."}
        ds = self._dbCheck(dRecv, "func")
        if "log" in ds:
            return ds
        i = ds["db"]
        t = dRecv["func"]
        dSend['res'] = i.getFunc(t)
        return dSend

    def _sendBtf(self, dRecv):
        arch = self._setupArch(dRecv)
        btfPath = os.path.join(btfDir, arch)
        os.chdir(btfPath)
        dSend = {'ver': dRecv['ver'], 'arch': arch}
        name = "vmlinux-%s" % dRecv['ver']
        try:
            with open(name, 'rb') as f:
                dSend['btf'] = segEncode(f.read()).decode()
                dSend['log'] = "ok."
        except IOError:
            dSend['log'] = "read btf file failed."
        return dSend

    def _transArch(self, arch):
        if arch == 'x86_64':
            return 'x86'
        return arch

    def _setupWorkPre(self, path):
        self._c.cmd(f"rm -rf {path}")
        os.mkdir(path)
        os.chdir(path)

    def _setupWorkEnd(self, path):
        os.chdir("../")
        self._c.cmd(f"rm -rf {path}")

    def _koBuild(self, dRecv):
        kos = dRecv.pop("kos")
        res = self._changeKoDir()
        if res['log'] != "ok.":
            return res
        dSend = {"log": "ok."}
        path = "tmp"
        with self._lock:
            self._setupWorkPre(path)
            for k, v in kos.items():
                with open(k, 'wb') as f:
                    f.write(segDecode(v))
            fns = CgenfuncsDb(dfFile, dRecv['arch'])
            fns.parse_kos('./')
            del fns         # confirm all data write to db
            with open(dfFile, 'rb') as f:
                dSend['db'] = segEncode(f.read()).decode()
            self._setupWorkEnd(path)
        return dSend

    def _compileSo(self, dRecv):
        dSend = {"log": "not start", "so": None}
        cStr = dRecv.pop("code")
        if "code" not in dRecv:
            return {"log": "no code."}
        if 'env' not in dRecv:
            dRecv['env'] = ""
        with self._lock:
            print("compile for %s" % dRecv['ver'])
            os.chdir(compileDir)
            with open("bpf/lbc.bpf.c", 'w') as f:
                f.write(cStr)
            if os.path.exists(soFile):
                os.remove(soFile)
            ver = dRecv['ver']
            arch = self._setupArch(dRecv)
            self._c.cmd("rm -f bpf/vmlinux.h")
            dSend['clog'] = self._c.cmd('make VMLINUX_VERSION=%s ARCH=%s CARCH=%s CLFLAG="%s"' % (ver,
                                                                                        arch,
                                                                                        self._transArch(arch),
                                                                                        dRecv['env']))
            print(dSend['clog'])
            try:
                with open(soFile, 'rb') as f:
                    dSend['so'] = base64.b64encode(f.read()).decode()
                dSend['log'] = "ok."
            except (OSError, IOError) as e:
                dSend['log'] = f"setup so report: {e}."
                print(dSend)
        return dSend

    def proc(self, dRecv):
        if "cmd" not in dRecv:
            dRecv['log'] = 'unknown request.'
            return dRecv

        if dRecv["cmd"] not in self._callDict:
            dRecv['log'] = 'unknown cmd.'
            return dRecv

        if "ver" not in dRecv:
            dRecv['log'] = 'no kernel version info.'
            return dRecv

        res = self._callDict[dRecv['cmd']](dRecv)
        udpPut(self._udpHost, dRecv)
        return res


if __name__ == "__main__":
    pass
