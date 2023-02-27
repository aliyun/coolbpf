//
// Created by 廖肇燕 on 2022/12/18.
//

#include "fastksym.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

static int tfd = 0;
static int sym_cnt = 0;
static struct ksym_cell * gCell = NULL;

static int load_ksyms(int fd, int stack_only) {
    int ret = 0;
    int count = 0;
    struct ksym_cell cell;
    void * addr;
    char buf[128];

    FILE *pf = fopen("/proc/kallsyms", "r");

    if (pf == NULL) {
        ret = -errno;
        fprintf(stderr, "open /proc/kallsyms failed, errno, %d, %s", errno, strerror(errno));
        goto endOpen;
    }

    while (!feof(pf)) {
        if (!fgets(buf, sizeof(buf), pf))
            break;

        ret = sscanf(buf, "%p %c %64s %31s", &addr, &cell.type, cell.func, cell.module);
        if (ret == 3) {
            cell.module[0] = '\0';
        } else if (ret < 3) {
            fprintf(stderr, "bad kallsyms line: %s", buf);
            goto endRead;
        }

        if (!addr)
            continue;

        if (stack_only && (cell.type != 't') && (cell.type != 'T')) {
            continue;
        }
        cell.addr = (addr_t) addr;

        ret = write(fd, &cell, sizeof (cell));
        if (ret < 0) {
            fprintf(stderr, "write file failed, errno, %d, %s", errno, strerror(errno));
            goto endWrite;
        }
        count ++;
    }

    fclose(pf);
    return count;

    endWrite:
    endRead:
    fclose(pf);
    endOpen:
    return ret;
}

static int sym_cmp(const void *p1, const void *p2)
{
    return ((struct ksym_cell *)p1)->addr > ((struct ksym_cell *)p2)->addr;
}

static int sort_ksym(int fd, int count) {
    int ret = 0 ;
    struct stat sb;
    void *pmmap;

    ret = fstat(fd, &sb);
    if (ret < 0) {
        fprintf(stderr, "fstat file failed, errno, %d, %s", errno, strerror(errno));
        goto endStat;
    }

    pmmap = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (pmmap == NULL) {
        fprintf(stderr, "mmap file failed, errno, %d, %s", errno, strerror(errno));
        ret = -EACCES;
        goto endMmap;
    }

    qsort(pmmap, count, sizeof (struct ksym_cell), sym_cmp);

    gCell = (struct ksym_cell*)pmmap;

    return ret;
    endMmap:
    endStat:
    return ret;
}

int ksym_setup(int stack_only) {
    int ret;

    FILE *pf = tmpfile();
    if (pf == NULL) {
        ret = -errno;
        fprintf(stderr, "open file failed, errno, %d, %s", errno, strerror(errno));
        goto endTmpfile;
    }

    tfd = fileno(pf);

    ret = load_ksyms(tfd, stack_only);
    if (ret < 0) {
        goto endLoad;
    }
    sym_cnt = ret;

    ret = sort_ksym(tfd, ret);
    if (ret < 0) {
        goto endSort;
    }

    return ret;
    endSort:
    endLoad:
    close(tfd);
    endTmpfile:
    return ret;
}

struct ksym_cell* ksym_search(addr_t key) {
    int start = 0, end = sym_cnt;
    int mid;

    if (sym_cnt <= 0) {
        printf("sym_cnt: %d", sym_cnt);
        return NULL;
    }

    while (start < end) {
        mid = start + (end - start) / 2;

        if (key < gCell[mid].addr) {
            end = mid;
        } else if (key > gCell[mid].addr) {
            start = mid + 1;
        } else {
            return &gCell[mid];
        }
    }

    if (start > 0) {
        if ((gCell[start - 1].addr < key) && (key < gCell[start].addr)) {
            return &gCell[start - 1];
        }
    }
    if (start == sym_cnt) {
        return &gCell[end - 1];
    }
    return NULL;
}
