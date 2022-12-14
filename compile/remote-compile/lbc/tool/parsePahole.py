import re
import sys
import os
import shlex
from subprocess import PIPE, Popen


class CexecCmd(object):
    def __init__(self):
        super(CexecCmd, self).__init__()
        pass

    @staticmethod
    def cmd(cmds):
        p = Popen(shlex.split(cmds), stdout=PIPE)
        return p.stdout.read().decode('utf-8').strip()

    @staticmethod
    def system(cmds):
        cmds = cmds.replace('\0', '').strip()
        return os.system(cmds)


class CparsePahole(CexecCmd):
    def __init__(self, objs):
        super(CparsePahole, self).__init__()
        if not os.path.exists(objs):
            raise Exception("obj file %s not exist." % objs)
        self._reIndex = re.compile(r"(?<=\[)[^\[\]]+(?=])")
        # self.__reStruct = re.compile(r"(?<={)[^{}]+(?=})")
        self._struct_mapping = {'char': 'c',
                                 'signed char': 'b',
                                 'unsigned char': 'B',
                                 '__s8': 'b',
                                 '__u8': 'b',
                                 's8': 'b',
                                 'u8': 'b',
                                 'char *': 's',
                                 'short': 'h',
                                 'unsigned short': 'H',
                                 '__s16': 'h',
                                 '__u16': 'H',
                                 's16': 'h',
                                 'u16': 'H',
                                 'int': 'i',
                                 'enum': 'i',
                                 'unsigned int': 'I',
                                 '__s32': 'i',
                                 '__u32': 'I',
                                 's32': 'i',
                                 'u32': 'I',
                                 'long long': 'q',
                                 'long': 'l',
                                 'long int': 'l',
                                 'unsigned long': 'L',
                                 'unsigned long long': 'Q',
                                 'long long unsigned int': 'Q',
                                 '__s64': 'q',
                                 '__u64': 'Q',
                                 's64': 'q',
                                 'u64': 'Q',
                                 'char []': 's',
                                 'void *': 'P'}
        self._typeSize = {'c': 1, 'b': 1, 'B': 1,
                           'h': 2, 'H': 2,
                           'i': 4, 'I': 4,
                           'l': 8, 'L': 8, 'Q': 8, 'q': 8,
                           's': 8, 'P': 8,
                           }
        self._objs = objs
        self._retStr = None

    def _getFormat(self, dMems):
        if dMems['type'] in self._struct_mapping:
            if dMems['array']:
                dMems['format'] = self._struct_mapping[dMems['type']] * dMems['array']
            else:
                dMems['format'] = self._struct_mapping[dMems['type']]
        else:
            raise Exception("unknown type: %s" % dMems['type'])

    def _getTopSize(self, dMems):
        dMems['size'] = self._typeSize[dMems['format'][0]]

    def _parseHead(self, tStr, dRet):
        if tStr[-1] == ']':
            t, _ = tStr.split('[', 1)
            dRet['type'] = t.strip()
            size = self._reIndex.findall(tStr)[0]
            dRet['array'] = int(size)
        else:
            dRet['type'] = tStr
            dRet['array'] = 0

    def _getTop(self, realType):
        dMems = {'member': 'value'}
        self._parseHead(realType, dMems)
        self._getFormat(dMems)
        self._getTopSize(dMems)
        return dMems

    def _getStructStr(self, sStruct):
        if self._retStr is None:
            self._retStr = self.cmd("pahole %s" % self._objs)
        find = "%s {" % sStruct
        start = self._retStr.index(find) + len(find)
        end = start + 1
        count = 1
        while count:
            c = self._retStr[end]
            if c == "{":
                count += 1
            elif c == '\0':
                raise Exception("bad pahole result.")
            elif c == '}':
                count -= 1
            end += 1
        return self._retStr[start:end - 1]

    # /* size: 44, cachelines: 1, members: 5 */
    def _getStrcutSize(self, ano):
        # print(ano)
        title, _ = ano.strip()[2:].split(',', 1)
        _, value = title.split(':')
        return int(value.strip())

    def _parseMember(self, desc):
        desc = re.sub(r" +", r" ", desc)
        # char c_comm[16]; /* 8 16 */
        var, annotate = desc.split(';', 1)
        tStr, member = var.strip().split(" ", 1)
        if ":" in member:
            raise ValueError("pylcc not support bit segment")
        if tStr.startswith('struct'):
            return self._getStruct(member)
        else:
            dMems = {'type': tStr}
            if member[-1] == ']':
                m, _ = member.split('[', 1)
                dMems['member'] = m.strip()
                size = self._reIndex.findall(member)[0]
                dMems['array'] = int(size)
            else:
                dMems['member'] = member
                dMems['array'] = 0
            self._getFormat(dMems)

        beg = annotate.index("/*") + 2
        end = annotate.index("*/")
        offs = annotate[beg:end].strip()
        offset, size = offs.split(' ')
        dMems['offset'] = int(offset)
        dMems['size'] = int(size)
        if dMems['array']:
            dMems['size'] = int(dMems['size'] / dMems['array'])
        return dMems

    def _getStruct(self, sStruct):
        #
        # 	u32                        c_pid;                /*     0     4 */
        # 	u32                        p_pid;                /*     4     4 */
        # 	char                       c_comm[16];           /*     8    16 */
        # 	char                       p_comm[16];           /*    24    16 */
        # 	u32                        stack_id;             /*    40     4 */
        #
        # 	/* size: 44, cachelines: 1, members: 5 */
        # 	/* last cacheline: 44 bytes */
        # }
        dStruct = {}
        self._parseHead(sStruct, dStruct)
        sDesc = self._getStructStr(dStruct['type'])
        descs = sDesc.split("\n")
        lMem = []
        sSize = "None"
        for desc in descs:
            s = desc.strip()
            if s == "":
                continue
            if s.startswith("/*"):
                if s.startswith('/* size'):
                    sSize = s
                continue
            lMem.append(self._parseMember(desc))
        dStruct['cells'] = lMem
        dStruct['offset'] = 0
        # /* size: 44, cachelines: 1, members: 5 */
        dStruct['size'] = self._getStrcutSize(sSize.strip())
        return dStruct

    def parseType(self, t):
        if t.startswith('struct '):
            return self._getStruct(t)
        else:
            return self._getTop(t)


if __name__ == "__main__":
    p = CparsePahole("../.output/lbc.bpf.o")
    print(p.parseType('struct data_t'))
