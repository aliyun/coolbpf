# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     generateUser
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
import os
import sys
import json
from checkSymbol import ClbcSymbol
# from parseArgs import CpaserGdbArgs
from parsePahole import CparsePahole
import hashlib


class CgenerateUser(object):
    def __init__(self, path='./'):
        self.__path = path
        self._skel = os.path.join(self.__path, '.output/lbc.skel.h')
        self._bpfc = os.path.join(self.__path, "bpf/lbc.bpf.c")
        self._bpfo = os.path.join(self.__path, '.output/lbc.bpf.o')
        self._reMaps = re.compile("struct bpf_map \\*[A-Za-z0-9_]+;")

    def upSkel(self, skel):
        self._skel = skel

    def getSkelMaps(self):
        rs = []
        with open(self._skel) as fSkel:
            line = fSkel.read()
            maps = self._reMaps.findall(line)
            for m in maps:
                t, v = m.rsplit("*", 1)
                rs.append(v[:-1])
        return rs

    def createUser(self, ver, arch, env="", oFile='src/bpf_init.c'):
        s = self.genModelInit()
        s += self.genModelMaps()
        s += self.genModelEvent()
        s += self.genModelSymbols(ver, arch, env)
        if not os.path.exists("src"):
            os.mkdir("src")
        with open(os.path.join(self.__path, oFile), 'w') as f:
            f.write(s)

    def genModelSymbols(self, ver, arch, env=""):
        a = CparsePahole(self._bpfo)
        dOut = {}
        dMaps = {}
        with open(self._bpfc, 'r') as f:
            sym = ClbcSymbol()
            s = f.read()
            s += env
            dOut['hash'] = hashlib.sha256(s).hexdigest()
            ds = sym.findEvent(s)
            for k, v in ds.items():
                dMaps[k] ={ 'type': v['type'], 'ktype': None, "vtype": a.parseType(v['vtype'])}
            hs = sym.findMaps(s)
            for k, v in hs.items():
                dMaps[k] = {'type': v['type'], 'ktype': a.parseType(v['ktype']), "vtype": a.parseType(v['vtype'])}
        dOut['maps'] = dMaps
        dOut['arch'] = arch
        dOut['kern_version'] = ver
        print(dOut['kern_version'])
        s = json.dumps(dOut).replace('"', '\\"')
        return """
const char* lbc_get_map_types(void)
{
    const char* s = "%s";
    return s;
}  
     
        """ % (s)

    def genModelEvent(self):
        return """
int lbc_set_event_cb(int id, void (*cb)(void *ctx, int cpu, void *data, unsigned int size), void (*lost)(void *ctx, int cpu, unsigned long long cnt))
{
    struct perf_buffer_opts pb_opts = {};
    struct bpf_object_skeleton *s;
    s = lbc_skel->skeleton;
    
    if (id >= s->map_cnt) {
        return -1;
    }
    pb_opts.sample_cb = cb;
    pb_opts.lost_cb = lost;
    lbc_maps[id].pb = perf_buffer__new(lbc_maps[id].mapFd, 8, &pb_opts);
    return libbpf_get_error(lbc_maps[id].pb); 
}

int lbc_event_loop(int id, int timeout)
{
    struct perf_buffer *pb;
    struct bpf_object_skeleton *s;
    int ret;
    
    s = lbc_skel->skeleton;
    if (id >= s->map_cnt) {
        return -1;
    }
    
    pb = (struct perf_buffer *)lbc_maps[id].pb;
    if (pb == NULL) {
        return -2;
    }
    while ((ret = perf_buffer__poll(pb, timeout)) >= 0) {
        ;
    }
    return ret;
}

int lbc_map_lookup_elem(int id, const void *key, void *value)
{
    int fd;
    struct bpf_object_skeleton *s;
    
    s = lbc_skel->skeleton;
    if (id >= s->map_cnt) {
        return -1;
    }
    
    fd = lbc_maps[id].mapFd;
    return bpf_map_lookup_elem(fd, key, value);
}

int lbc_map_lookup_and_delete_elem(int id, const void *key, void *value)
{
    int fd;
    struct bpf_object_skeleton *s;
    
    s = lbc_skel->skeleton;
    if (id >= s->map_cnt) {
        return -1;
    }
    
    fd = lbc_maps[id].mapFd;
    return bpf_map_lookup_and_delete_elem(fd, key, value);
}

int lbc_map_delete_elem(int id, const void *key)
{
    int fd;
    struct bpf_object_skeleton *s;
    
    s = lbc_skel->skeleton;
    if (id >= s->map_cnt) {
        return -1;
    }
    
    fd = lbc_maps[id].mapFd;
    return bpf_map_delete_elem(fd, key);
}

int lbc_map_get_next_key(int id, const void *key, void *next_key)
{
    int fd;
    struct bpf_object_skeleton *s;
    
    s = lbc_skel->skeleton;
    if (id >= s->map_cnt) {
        return -1;
    }
    
    fd = lbc_maps[id].mapFd;
    return bpf_map_get_next_key(fd, key, next_key);
}
        """

    def genModelMaps(self):
        return """
#define MAPS_NAME_MAX 32
#define MAPS_CELL_MAX 256
struct lbc_maps_struct {
    char name[MAPS_NAME_MAX];
    int type;
    int mapFd;
    void *pb;
};
static struct lbc_maps_struct lbc_maps[MAPS_CELL_MAX];
int lbc_bpf_mmap_maps(void)
{
    int i;
    struct bpf_object_skeleton *s;
    s = lbc_skel->skeleton;
    for (i = 0; i < s->map_cnt; i ++) {
        strncpy(lbc_maps[i].name, s->maps[i].name, MAPS_NAME_MAX);
        lbc_maps[i].mapFd = bpf_map__fd(*(s->maps[i].map));
        if (lbc_maps[i].mapFd < 0) {
            fprintf(stderr, "Failed to get map_fd\\n");
            return -1;
        }
    }
    return 0;
}

int lbc_bpf_get_maps_id(char* event)
{
    int i;
    struct bpf_object_skeleton *s;
    s = lbc_skel->skeleton;
    for (i = 0; i < s->map_cnt; i ++) {
        if (strncmp(lbc_maps[i].name, event, MAPS_NAME_MAX) == 0) {
            return i;
        }
    }
    return -1;
}
        """

    def genModelInit(self):
        return r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <lbc.skel.h>

#define MAX_SYMS 300000
struct ksym {
    long addr;
    char *name;
};

static struct ksym* syms = NULL;
static int sym_cnt;

static int ksym_cmp(const void *p1, const void *p2)
{
    return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

#define FUNC_LEN_MAX 256
int load_kallsyms(void)
{
    FILE *f = fopen("/proc/kallsyms", "r");
    int ret;
    char func[FUNC_LEN_MAX], buf[FUNC_LEN_MAX], ko[FUNC_LEN_MAX];
    char symbol;
    void *addr;
    int i = 0;

    if (!f)
        return -ENOENT;

    while (!feof(f)) {
        if (!fgets(buf, sizeof(buf), f))
            break;
        ret = sscanf(buf, "%p %c %s %s", &addr, &symbol, func, ko);
        if (ret == 4) {
            strncat(func, " ", FUNC_LEN_MAX -1);
            strncat(func, ko, FUNC_LEN_MAX -1);
            func[FUNC_LEN_MAX -1] = '\0';
        }
        else if (ret != 3) {
            break;
        }
        if (!addr)
            continue;
        syms[i].addr = (long) addr;
        syms[i].name = strdup(func);
        i++;
    }
    fclose(f);
    sym_cnt = i;
    qsort(syms, sym_cnt, sizeof(struct ksym), ksym_cmp);
    return 0;
}

struct ksym *ksym_search(long key)
{
    int start = 0, end = sym_cnt;
    int result;
    
    if (syms == NULL) {
        syms = malloc(sizeof(struct ksym) * MAX_SYMS);
        if (syms == NULL)
            return NULL;
        if (load_kallsyms()) {
            free(syms);
            return NULL;
        }
    }
    
    /* kallsyms not loaded. return NULL */
    if (sym_cnt <= 0)
        return NULL;

    while (start < end) {
        size_t mid = start + (end - start) / 2;

        result = key - syms[mid].addr;
        if (result < 0)
            end = mid;
        else if (result > 0)
            start = mid + 1;
        else
            return &syms[mid];
    }

    if (start >= 1 && syms[start - 1].addr < key &&
        key < syms[start].addr)
    /* valid ksym */
        return &syms[start - 1];

    /* out of range. return _stext */
    return &syms[0];
}

long ksym_get_addr(const char *name)
{
    int i;

    for (i = 0; i < sym_cnt; i++) {
        if (strcmp(syms[i].name, name) == 0)
            return syms[i].addr;
    }
    return 0;
}

static int log_level = LIBBPF_WARN;
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (log_level >=0 && level <= log_level) {
        return vfprintf(stderr, format, args);
    }
    return 0;
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
            .rlim_cur	= RLIM_INFINITY,
            .rlim_max	= RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\\n");
        exit(1);
    }
}

static struct lbc_bpf *lbc_skel = NULL;
int lbc_bpf_mmap_maps(void);
int lbc_bpf_init(int level)
{
    int err;
    int map_my_map_fd;
    struct perf_buffer_opts pb_opts = {};
    
    log_level = level;

    libbpf_set_print(libbpf_print_fn);
    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    /* Open BPF application */
    lbc_skel = lbc_bpf__open();
    if (!lbc_skel) {
        fprintf(stderr, "Failed to open BPF skeleton\\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = lbc_bpf__load(lbc_skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = lbc_bpf__attach(lbc_skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\\n");
        goto cleanup;
    }
    
    err = lbc_bpf_mmap_maps();
    if (err) {
        goto cleanup;
    }

    return 0;
    cleanup:
    lbc_bpf__destroy(lbc_skel);
    return -err;
}

void lbc_bpf_exit(void)
{
    lbc_bpf__destroy(lbc_skel);
}

        """


if __name__ == "__main__":
    g = CgenerateUser()
    if len(sys.argv) <= 3:
        g.createUser(sys.argv[1], sys.argv[2])
    else:
        g.createUser(sys.argv[1], sys.argv[2], sys.argv[3])
