# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     getVmlinux
   Description :
   Author :       liaozhaoyan
   date：          2021/12/1
-------------------------------------------------
   Change Activity:
                   2021/12/1:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
import os
import shlex
from subprocess import PIPE, Popen
from getFuncs import CgetVminfo, CgenfuncsDb

HivePath = "/home/vmhive/aarch64/"
VMPath = HivePath + "vmlinux/"
BTFPath = HivePath + "btf/"
HeadPath = HivePath + "header/"
FuncPath = HivePath + "funcs/"
DBPath = HivePath + "db/"
PkgPath = HivePath + "pkg/"
RVMPath = PkgPath

class CexecCmd(object):
    def __init__(self):
        super(CexecCmd, self).__init__()

    @staticmethod
    def cmd(cmds):
        p = Popen(shlex.split(cmds), stdout=PIPE)
        return p.stdout.read().decode().strip()

    @staticmethod
    def system(cmds):
        cmds = cmds.replace('\0', '').strip()
        return os.system(cmds)

class CgetVmlinux(CexecCmd):
    def __init__(self):
        super(CgetVmlinux, self).__init__()

    def drpm(self, path):
        self.system("rpm2cpio %s|cpio -id" % path)

    def ddeb(self, path):
        self.cmd("ar x %s" % path)
        if os.path.exists("data.tar.xz"):
            self.cmd("xz -d data.tar.xz")
            self.cmd("tar xf data.tar")
        else:
            self.cmd("tar -I zstd -xvf data.tar.zst")

    def _genRpmVer(self, name):
        _, _, n = name.split("-", 2)
        ver, _ = n.rsplit(".", 1)
        return ver

    #linux-image-3.13.0-96-generic-dbgsym_3.13.0-96.143_i386.ddeb -> 3.13.0-96-generic
    def _genDebVer(self, name):
        if name.startswith("linux-image-unsigned"):
            _, _, _, n = name.split("-", 3)
        else:
            _, _, n = name.split("-", 2)
        ver, _ = n.split("-dbgsym", 1)
        return ver

    def copyVmlinuxRpm(self, name, release):
        res = self.cmd("find ./ -name vmlinux").strip("\n")
        ver = self._genRpmVer(name)
        dPath = VMPath + "%s/vmlinux-%s" % (release, ver)
        cmd = "cp %s %s" % (res, dPath)
        self.cmd(cmd)
        return [ver, release, dPath]

    def copyVmlinuxDeb(self, name, release):
        res = self.cmd("find ./ -name vmlinux*").strip("\n").split('\n')
        for r in res:
            if os.path.isfile(r) and not r.endswith("decompressor"):
                ver = self._genDebVer(name)
                dPath = VMPath + release +"/vmlinux-%s" % ver
                cmd = "cp %s %s" % (r, dPath)
                self.cmd(cmd)
                break
        return [ver, release, dPath]

    def checkProc(self, name, release):
        if name.endswith(".rpm"):
            ver = self._genRpmVer(name)
        elif name.endswith(".ddeb"):
            ver = self._genDebVer(name)
        else:
            return True
        funsPath = FuncPath + "%s/funs-%s.txt" % (release, ver)
        btfPath = BTFPath + "%s/vmlinux-%s" % (release, ver)
        dbPath = DBPath + "%s/info-%s.db" % (release, ver)
        vmPath = VMPath + "%s/vmlinux-%s" % (release, ver)
        if os.path.exists(dbPath):
            return True
        if os.path.exists(funsPath) and os.path.exists(btfPath):
            self._genDb(ver, release)
            return True
        if os.path.exists(vmPath):
            self.genOthers(ver, release, vmPath)
            return True
        return False

    def _check_mount(self):
        if not os.path.exists(f"{PkgPath}flag"):
            pass
            # self.cmd("sshfs root@47.113.194.53:/root/1ext/down/pkg /home/vmhive/pkg/")

    def _proc_work(self, url, name, release):
        pkg = f"{PkgPath}{name}"

        # self._check_mount()
        # if os.path.exists(pkg) and not os.path.exists(f"{pkg}.st"):
        #     self.cmd(f"cp {pkg} ./")
        # else:
        self.cmd("axel -n 4 %s" % url)
        res = None
        if not os.path.exists(name):
            raise Exception("failed to get file.")
        if name.endswith(".rpm"):
            self.drpm(name)
            res = self.copyVmlinuxRpm(name, release)
        elif name.endswith(".ddeb"):
            self.ddeb(name)
            res = self.copyVmlinuxDeb(name, release)
        # self._check_mount()
        # if os.path.exists(pkg) and not os.path.exists(f"{pkg}.st"):
        #     self.cmd(f"rm -f {pkg}")
        return res

    def _check_remote_vm(self, name, release):
        return None
        # self._check_mount()
        # if name.endswith(".rpm"):
        #     ver = self._genRpmVer(name)
        # elif name.endswith(".ddeb"):
        #     ver = self._genDebVer(name)
        # else:
        #     return None
        # sPath = RVMPath + "vmlinux-%s" % ver
        # if not os.path.exists(sPath):
        #     return None
        # dPath = VMPath + "%s/vmlinux-%s" % (release, ver)
        # cmd = "cp %s %s" % (sPath, dPath)
        # self.cmd(cmd)
        # return [ver, release, dPath]

    def proc(self, url, name, release):
        if self.checkProc(name, release):
            return
        res = self._check_remote_vm(name, release)
        if res is None:
            lastWork = os.getcwd()
            self.cmd("rm -rf work")
            os.mkdir("work")
            os.chdir("work")
            res = self._proc_work(url, name, release)
            os.chdir(lastWork)
            self.cmd("rm -rf work")
        if res is not None:
            self.genOthers(*res)

    def _genBtfHead(self, ver, release, vmPath):
        btfPath = BTFPath + "%s/vmlinux-%s" % (release, ver)
        headPath = HeadPath + "%s/vmlinux-%s.h" % (release, ver)
        self.cmd("cp %s %s" % (vmPath, btfPath))
        self.cmd("pahole -J %s" % btfPath)
        self.cmd("llvm-objcopy --only-section=.BTF --set-section-flags .BTF=alloc,readonly --strip-all %s" % btfPath)
        self.cmd("aarch64-linux-gnu-strip -x %s" % btfPath)
        if os.path.exists(f"{btfPath}.btf"):
            self.cmd(f"rm -f {btfPath}")
            self.cmd(f"mv {btfPath}.btf {btfPath}")
        self.system("bpftool btf dump file %s format c > %s" % (btfPath, headPath))

    def _getFuns(self, ver, release, vmPath):
        funsPath = FuncPath + "%s/funs-%s.txt" % (release, ver)
        g = CgetVminfo(vmPath)
        g.genFile(funsPath)

    def _genDb(self, ver, release):
        funsPath = FuncPath + "%s/funs-%s.txt" % (release, ver)
        btfPath = BTFPath + "%s/vmlinux-%s" % (release, ver)
        dbPath = DBPath + "%s/info-%s.db" % (release, ver)
        vmPath = VMPath + "%s/vmlinux-%s" % (release, ver)

        print(f"gen {dbPath}")
        db = CgenfuncsDb(dbPath)
        self.system(f"pahole {btfPath} > struct.txt")
        db.funcs(funsPath)
        db.structs("struct.txt")
        db.types(vmPath)

    def genOthers(self, ver, release, vmPath):
        self._genBtfHead(ver, release, vmPath)
        self._getFuns(ver, release, vmPath)
        self._genDb(ver, release)

if __name__ == "__main__":
    pass
