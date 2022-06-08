# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     getFuncs
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
import select
import sqlite3
import json
import re

ON_POSIX = 'posix' in sys.builtin_module_names

class CasyncCmdQue(object):
    def __init__(self, cmd):
        super(CasyncCmdQue, self).__init__()
        self.daemon = True  # thread dies with the program
        self.__p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, close_fds=ON_POSIX)
        self.__e = select.epoll()
        self.__e.register(self.__p.stdout.fileno(), select.EPOLLIN)

    def __del__(self):
        self.__p.kill()

    def write(self, cmd):
        try:
            self.__p.stdin.write(cmd.encode())
            self.__p.stdin.flush()
        except IOError:
            return -1

    def writeLine(self, cmd):
        self.write(cmd + "\n")

    def read(self, tmout=0.2, l=16384):
        while True:
            es = self.__e.poll(tmout)
            if not es:
                return ""
            for f, e in es:
                if e & select.EPOLLIN:
                    s = os.read(f, l).decode()
                    return s

    def readw(self, want, tries=100):
        i = 0
        r = ""
        while i < tries:
            line = self.read()
            if want in line:
                return r + line
            r += line
            i += 1
        raise Exception("get want args %s overtimes" % want)

    def terminate(self):
        self.__p.terminate()
        return self.__p.wait()

class CgetVminfo(object):
    def __init__(self, vmPath):
        super(CgetVminfo, self).__init__()
        self._gdb = CasyncCmdQue("gdb %s" % vmPath)
        self._gdb.readw("(gdb)", 500)
        self._gdb.writeLine("set pagination off")
        self._gdb.readw("(gdb)")

    def genType(self, t):
        self._gdb.writeLine(f"ptype {t}")
        r = self._gdb.readw("(gdb)").split("\n")[0]
        try:
            _, alias = r.split("=", 1)
        except ValueError:
            return [None, None]
        alias = alias.strip()

        self._gdb.writeLine(f"p sizeof({t})")
        r = self._gdb.readw("(gdb)").split("\n")[0]
        _, size = r.split("=", 1)
        size = int(size.strip())
        return [alias, size]

    def genFile(self, fName="funs.txt"):
        self._gdb.writeLine("i functions")
        with open(fName, 'w') as f:
            s = "dummy"
            while "\n(gdb)" not in s:
                s = self._gdb.read(tmout=240)
                f.write(s)

class CgenfuncsDb(object):
    def __init__(self, dbName):
        # self._txt = txt
        self._db = None
        self._vm = None
        # dbName = self._parseName()
        self._setupDb(dbName)

    def __del__(self):
        if self._db is not None:
            self._db.commit()
            self._db.close()

    def _setupDb(self, dbName):
        if os.path.exists(dbName):
            os.remove(dbName)
        self._db = sqlite3.connect(dbName)
        cur = self._db.cursor()
        sql = """CREATE TABLE files ( 
                          id INTEGER PRIMARY KEY autoincrement,
                          file TEXT
                );"""
        cur.execute(sql)
        sql = """CREATE TABLE funs ( 
                  id INTEGER PRIMARY KEY autoincrement,
                  func VARCHAR (128),
                  args JSON,
                  ret VARCHAR (64),
                  line INTEGER,
                  fid INTEGER
        );"""
        cur.execute(sql)
        sql = """CREATE TABLE structs ( 
                          id INTEGER PRIMARY KEY autoincrement,
                          name VARCHAR (64),
                          members INTEGER,
                          bytes INTEGER
                );"""
        cur.execute(sql)
        sql = """CREATE TABLE members ( 
                                  id INTEGER PRIMARY KEY autoincrement,
                                  fid INTEGER,
                                  types VARCHAR (128),
                                  name VARCHAR (64),
                                  offset INTEGER,
                                  bytes INTEGER,
                                  bits VARCHAR (16) DEFAULT ""
                        );"""
        cur.execute(sql)
        sql = """CREATE TABLE types ( 
                                  id INTEGER PRIMARY KEY autoincrement,
                                  name VARCHAR (64),
                                  alias VARCHAR (64),
                                  bytes INTEGER
                        );"""
        cur.execute(sql)
        cur.close()

    def _arg_split(self, argStr):
        args = []
        arg  = ""
        count = 0

        for a in argStr:
            if count == 0 and a == ",":
                args.append(arg.strip())
                arg = ""
                continue
            elif a == "(":
                count += 1
            elif a == ")":
                count -= 1
            arg += a
        if arg != "":
            args.append(arg.strip())
        return args

    def funcs(self, funcPath):
        cur = self._db.cursor()
        with open(funcPath, 'r') as f:
            fid = 0
            for index, line in enumerate(f):
                line = line[:-1]
                if line == "":
                    continue
                elif line.startswith("(gdb)"):
                    break
                elif line.startswith("File "):
                    _, sFile = line.split(" ", 1)
                    sql = f'''INSERT INTO files (file) VALUES ("{sFile[:-1]}")'''
                    cur.execute(sql)
                    fid = cur.lastrowid
                elif line.endswith(");"):
                    #8:	static int __paravirt_pgd_alloc(struct mm_struct *);
                    line = line[:-2]
                    lineNo, body = line.split(":", 1)
                    head, args = body.split("(", 1)
                    # args = [x.strip() for x in args.split(",")]
                    args = self._arg_split(args)
                    if "*" in head:
                        ret, func = head.rsplit("*", 1)
                        ret += "*"
                    else:
                        ret, func = head.rsplit(" ", 1)
                    sql = f'''INSERT INTO funs (func, args, ret, line, fid) VALUES \
                    ("{func}", '{json.dumps(args)}', "{ret.strip()}", {lineNo}, {fid})'''
                    cur.execute(sql)
        cur.close()

    def _insStructs(self, cur, lines):
        name, _ = lines[0].rsplit(" ", 1)
        ds = {"members": 0, "size":0}
        for line in lines[::-1]:
            if "/* size" in line:
                """ /* size: 16, cachelines: 1, members: 2 */"""
                l = line.strip()
                beg = l.index("/*") + 2
                end = l.index("*/")
                l = l[beg:end]
                vs = l.split(",")
                for c in vs:
                    k, v = c.split(":")
                    ds[k.strip()] = v.strip()
        sql = f'''INSERT INTO structs (name, members, bytes) VALUES \
                            ("{name}", {ds["members"]}, {ds["size"]})'''
        cur.execute(sql)
        return cur.lastrowid

    def _parseMember(self, cur, fid, line, pre=""):
        """struct list_head *         next;                 /*     0     8 */"""
        """void (*func)(struct callback_head *); /*     8     8 */"""
        """unsigned int               p:1;                  /*     4:15  4 */"""
        if ";" not in line:
            return
        bits = ""
        body, anno = line.split(";")
        if "/*" not in anno:
            return

        if body[-1] == ")": #func
            _, func = body.split("(*", 1)
            func, _ = func.split(")", 1)
            types = body.replace(f" (*{func})(", " (*)(", 1)
            types = re.sub(" +", " ", types)
            name = func
        else:
            types, name = body.rsplit(" ", 1)
            types = types.strip()
            name = name.strip()
            if ":" in name:
                name, bits = name.split(":", 1)
        name = pre + name

        beg = anno.index("/*") + 2
        end = anno.index("*/")
        l = anno[beg:end].strip()
        offset, bytes = l.rsplit(" ", 1)
        offset = offset.strip()
        if ":" in offset:
            offset, start = offset.split(":", 1)
            bits = start.strip() + ":" + bits

        sql = f'''INSERT INTO members (fid, types, name, offset, bytes, bits) VALUES \
                            ({fid}, "{types}", "{name}", {offset.strip()}, {bytes.strip()}, "{bits}")'''
        cur.execute(sql)

    def _parseBox(self, cur, fid, lines, pre):
        """union {"""
        """} pci;"""
        t = lines[0].split(" ", 1)[0]
        if t in ["union", "struct"]:
            lastLine = lines[-1]
            if not lastLine.startswith("};"):
                npre, _ = lastLine[1:].split(";", 1)
                _, npre = npre.rsplit(" ", 1)
                pre += npre.strip() + "."
            self._parseLoop(cur, fid, lines, pre)

    def _parseLoop(self, cur, fid, lines, pre):
        qCount = 0
        box = []
        for line in lines[1:-1]:
            line = line.strip()
            if line.startswith("/* size:"):
                break
            lCount = line.count("{")
            rCount = line.count("}")
            qCount += lCount - rCount
            if qCount > 0:
                box.append(line)
            elif len(box) > 0:
                box.append(line)
                self._parseBox(cur, fid, box, pre)
                box = []
            else:
                self._parseMember(cur, fid, line, pre)

    def _parseStruct(self, cur, lines):
        fid = self._insStructs(cur, lines)
        self._parseLoop(cur, fid, lines, "")

    def structs(self, fName):
        cur = self._db.cursor()
        with open(fName, 'r') as f:
            lines = []
            for index, line in enumerate(f):
                lines.append(line)
                if line.startswith("}"):
                    self._parseStruct(cur, lines)
                    lines = []
        cur.close()

    def _save_type(self, cur, t):
        alias, size = self._vm.genType(t)
        if alias:
            sql = f'INSERT INTO types (name, alias, bytes) VALUES ("{t}", "{alias}", {size})'
            cur.execute(sql)

    def _type_is_in(self, cur, t):
        sql = f"SELECT name FROM types WHERE name = '{t}'"
        res = cur.execute(sql)
        if res is None:
            return False
        r = res.fetchone()
        if r is None:
            return False
        return True

    def _is_types(self, t):
        if "*" in t:
            return None
        if t.startswith("const "):
            t = t[6:]
        if t.startswith("static "):
            t = t[7:]
        if t.startswith("volatile "):
            t = t[8:]
        if t.startswith("struct ") or t.startswith("union ") or t.startswith("enum "):
            return None
        if t in ("void", "..."):
            return None
        return t

    def _check_type(self, cur, t):
        t = self._is_types(t)
        if t and not self._type_is_in(cur, t):
            self._save_type(cur, t)

    def _type(self, args, ret):
        if args is not None:
            args = json.loads(args)
        else:
            args = []
        args.append(ret)

        cur = self._db.cursor()
        for arg in args:
            self._check_type(cur, arg)
        cur.close()

    def types(self, vmlinux):
        cur = self._db.cursor()
        self._vm = CgetVminfo(vmlinux)
        self._save_type(cur, "void *")
        sql = "SELECT args, ret FROM funs"
        res = cur.execute(sql)
        if res is None:
            return
        r = res.fetchone()
        while r is not None:
            self._type(*r)
            r = res.fetchone()
        sql = "SELECT types FROM members"
        res = cur.execute(sql)
        if res is None:
            return
        r = res.fetchone()
        while r is not None:
            self._type(None, r[0])
            r = res.fetchone()
        cur.close()

if __name__ == "__main__":
    d = CgenfuncsDb("info-4.19.91-25.al7.x86_64.db")
    os.system("pahole /home/vmhive/vmlinux/alinux/vmlinux-4.19.91-25.al7.x86_64 > struct.txt")
    d.structs("struct.txt")
    d.funcs("/home/vmhive/funcs/alinux/funs-4.19.91-25.al7.x86_64.txt")
    d.types("/home/vmhive/vmlinux/alinux/vmlinux-4.19.91-25.al7.x86_64")
    pass
