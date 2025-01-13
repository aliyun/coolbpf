#include <unistd.h> 
#include <stdlib.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#include "perf_sample.h"
#include "perf_handle.h"


typedef u64 addr_t;

#define NR_CPU_NUM 1024
#define SAMPLE_STACK_USER 32
#define SAMPLE_STACK_KERNEL 32
#define SAMPLE_STACK_USER_SIZE (32 * 1024)
#define NR_PER_RING 512  // 一个perf 占用 512 个page.
#define PERF_SAMPLE_FLAG (PERF_SAMPLE_TID | PERF_SAMPLE_REGS_USER | PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_STACK_USER)
static int cpus = -1;
static int per_page_size = 4096;
static addr_t per_map_mask = 0;

typedef struct{
    addr_t perf_addr;
    int perf_fd;
}perf_sample_cell_t;

static void perf_sample_cell_copy(void *_dst, const void *_src) {
    perf_sample_cell_t *dst = (perf_sample_cell_t*)_dst, *src = (perf_sample_cell_t*)_src;
    dst->perf_addr = src->perf_addr;
    dst->perf_fd = src->perf_fd;
}

static void perf_sample_cell_dtor(void *_elt) {
    perf_sample_cell_t *elt = (perf_sample_cell_t*)_elt;
    if (elt->perf_fd > 0) {
        ioctl(elt->perf_fd, PERF_EVENT_IOC_DISABLE, 0);
        close(elt->perf_fd);
    }
    if (elt->perf_addr != 0) {
        munmap((void *)elt->perf_addr, (NR_PER_RING + 1) * per_page_size);
    }
}

const static UT_icd perf_sample_icd = {sizeof(perf_sample_cell_t), NULL, perf_sample_cell_copy, perf_sample_cell_dtor};

static long perf_event_open(struct perf_event_attr *event, pid_t pid,
                int cpu, int group_id, unsigned long flags) {
        return syscall(__NR_perf_event_open, event, pid, cpu, group_id, flags);
}

static int perf_sw_event(struct perf_event_attr* attr, int freq, int flag) {
    memset(attr, 0, sizeof(struct perf_event_attr));
    attr->disabled = 1;
    attr->size = sizeof(*attr);
    attr->type = PERF_TYPE_SOFTWARE;
    attr->config = PERF_COUNT_SW_CPU_CLOCK;
    attr->sample_type = flag;
    attr->exclude_hv = 1;
    attr->exclude_idle = 0;
    attr->freq = 1;
    attr->sample_freq = freq;
    attr->sample_regs_user = PERF_REG_MASK;
    attr->sample_stack_user = SAMPLE_STACK_USER_SIZE;
    return attr->sample_type;
}

static int perf_create_event(int freq, int cpu, int flag) {
    struct perf_event_attr attr;
    perf_sw_event(&attr, freq, flag);
    return perf_event_open(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
}

addr_t perf_mmap(int fd) {
    struct perf_event_mmap_page *pcp;
    pcp = (struct perf_event_mmap_page *)mmap(NULL, (NR_PER_RING + 1) * per_page_size,
            PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (pcp == MAP_FAILED) {
        perror("mmap fd failed.");
        return 0;
    }
    return (addr_t)pcp;
}

static int perf_fds_create(UT_array *array, int freq, int flag) {
    int i, ret, fd;
    addr_t addr;

    for (i = 0; i < cpus; i ++) {
        fd = perf_create_event(freq, i, flag);
        if (fd < 0) {
            if (errno == ENODEV) {
                printf("cpu %d not support perf event\n", i);
                continue;
            }
            perror("syscall failed.");
            goto create_failed;
        }
        addr = perf_mmap(fd);
        if (addr == 0) {
            close(fd);
            goto mmap_failed;
        }
        perf_sample_cell_t cell = {
            .perf_addr = addr,
            .perf_fd = fd,
        };
        utarray_push_back(array, &cell);
    }
    return 0;
mmap_failed:
create_failed:
    return -1;
}

static int perf_live_ioctl_start(UT_array *array) {
    int i, ret;
    int len = utarray_len(array);
    for (i = 0; i < len; i ++) {
        perf_sample_cell_t* cell = (perf_sample_cell_t*)utarray_eltptr(array, i);
        int fd = cell->perf_fd;
        ret = ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        if (ret < 0) {
            perror("ioctl PERF_EVENT_IOC_RESET");
            return -1;
        }
        ret = ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
        if (ret < 0) {
            perror("ioctl PERF_EVENT_IOC_ENABLE");
            return -1;
        }
    }
    return 0;
}

void perf_live_init(void){
    cpus = sysconf(_SC_NPROCESSORS_ONLN);
    per_page_size = sysconf(_SC_PAGE_SIZE);
    per_map_mask = per_page_size * NR_PER_RING - 1;
}

static void* perf_live_new_sample(int (*cb)(perf_sample_t* sample)){
    perf_sample_handle_t* h = (perf_sample_handle_t *)malloc(sizeof(perf_sample_handle_t));
    utarray_new(h->array, &perf_sample_icd);
    h->cb = cb;
    return h;
}

void perf_live_free_sample(void* handle) {
    perf_sample_handle_t* h = (perf_sample_handle_t *)handle;
    utarray_free(h->array);
    free(h);
}

void* perf_live_on_start(int freq, int (*cb)(perf_sample_t* sample)) {
    int i, ret;
    if (cpus < 0) {
        perf_live_init();
    }
    if (cpus == 0) {
        return NULL;
    }
    perf_sample_handle_t* h = (perf_sample_handle_t *)perf_live_new_sample(cb);
    h->flag = PERF_SAMPLE_FLAG;

    ret = perf_fds_create(h->array, freq, h->flag);
    if (ret < 0) {
        goto create_failed;
    }

    ret = perf_live_ioctl_start(h->array);
    if (ret < 0) {
        goto ioctl_failed;
    }
    return h;

create_failed:
ioctl_failed:
    perf_live_free_sample(h);
    return NULL;
}

void perf_live_on_stop(void *handle) {
    // fd will close in 
    perf_live_free_sample(handle);
}

struct perf_record_sample {
    struct perf_event_header header;
    regs_t array[0];
};

static inline regs_t* perf_sample_addr(struct perf_record_sample *e, int offset){
    return (regs_t*)((u8*)&(e->array[0]) + offset);
}

static void perf_sample_check(struct perf_record_sample *e, perf_sample_t* sample,
                              perf_sample_handle_t* h
) {
    int header_size = offsetof(perf_sample_t, callchain_nr) + sizeof(struct perf_event_header);
    int total_size = header_size + \
                    sizeof(regs_t) + \
                    sizeof(regs_t) * sample->callchain_nr + \
                    sizeof(regs_t) + \
                    sizeof(regs_t) * sample->user_regs_nr + \
                    sizeof(regs_t) + \
                    sample->stack_size;
    if (e->header.size != total_size ) {
        fprintf(stderr, "size is not %d, %d\n", total_size, e->header.size);
        fprintf(stderr, "callchain_nr: %ld, user_regs_nr: %ld, stack_size: %ld\n", 
                sample->callchain_nr,
                sample->user_regs_nr,
                sample->stack_size
        );
        abort();
    }
    if (sample->user_regs_nr > 0 && sample->stack_size == 0) {
        fprintf(stderr, "stack_size is 0 when user_regs_nr is not 0.\n");
        abort();
    }
    h->cb(sample);
}

// perf sample stack:
// pid(u32), tid(u32), 
// callchain_nr(regs_t), 
// callchain(callchain_nr * regs_t, optional), 
// user_regs_nr(regs_t)
// user_regs(user_regs_nr * regs_t, optional), 
// user_stack_size(regs_t should be SAMPLE_STACK_USER_SIZE * regs_t or 0, only use stack sample)
// user_stack(user_stack_size * regs_t, optional)
static int _perf_process(struct perf_record_sample *e, perf_sample_handle_t* h) {
    int callchain_offset = offsetof(perf_sample_t, callchain);
    int now_cur;

    perf_sample_t sample;
    memset(&sample, 0, sizeof(sample));

    memcpy(&sample, e->array, callchain_offset);  //  copy pid, tid, and callchain_nr;
    if (sample.callchain_nr == 0) {
        fprintf(stderr, "callchain_nr is 0, should never happen.\n");
        abort();
    } else {
        sample.callchain = perf_sample_addr(e, callchain_offset);
    }
    now_cur = callchain_offset + sizeof(regs_t) * sample.callchain_nr;

    regs_t* p_user_regs_nr = perf_sample_addr(e, now_cur);
    sample.user_regs_nr = *p_user_regs_nr;
    if (sample.user_regs_nr == 0) {  // no user regs, stack is in kernel
        sample.user_regs = NULL;  // no user regs

        sample.chain_user = NULL;
        sample.chain_user_size = 0;
        sample.chain_kernel = &sample.callchain[1];  // for x86, start from 1
        sample.chain_kernel_size = sample.callchain_nr - 1;
    } else {  // user regs, stack is in user
        
        if (sample.user_regs_nr != PERF_MAX_REGS) {
            // if fp is the same to sp, then user_regs_nr is not PERF_MAX_REGS, should adjust to PERF_MAX_REGS.
            // fprintf(stderr, "user_regs_nr is %d, should be %d, fix it.\n", sample.user_regs_nr, PERF_MAX_REGS);
            sample.user_regs_nr = PERF_MAX_REGS;
        }
        sample.user_regs = perf_sample_addr(e, now_cur + sizeof(regs_t));  // has user regs

        int i;
        sample.chain_kernel = &sample.callchain[1]; // has kernel and user stack.
        for (i = 2; i < sample.callchain_nr; i ++) {
            if (STACK_IS_USER(sample.callchain[i])) { // split user stack.
                sample.chain_kernel_size = i - 2;
                break;
            }
        }
        sample.chain_user = &sample.callchain[i - 1];
        sample.chain_user_size = sample.callchain_nr - i + 1;
        
    }
    now_cur += sizeof(regs_t) + sizeof(regs_t) * sample.user_regs_nr;

    regs_t* p_user_stack_size = perf_sample_addr(e, now_cur);
    sample.stack_size = *p_user_stack_size;
    if (sample.stack_size == 0) {
        sample.stack = NULL;
    } else {
        sample.stack = perf_sample_addr(e, now_cur + sizeof(regs_t));
        sample.stack_size += sizeof(regs_t);  // 加上stack_size 数据空间。
        printf("sample stack size: %ld\n", sample.stack_size);
    }
    perf_sample_check(e, &sample, h);
    return 0;
}

//struct perf_event_header {
 //       __u32   type;
 //       __u16   misc;
 //        __u16   size;
 //};
 //struct perf_record_sample {
 //        struct perf_event_header header;
 //        __u64                    array[0];
 //};
static int _perf_sample(const addr_t begin, const addr_t end,
                        const addr_t cur,   struct perf_record_sample *e,
                        perf_sample_handle_t* h
                        ) {
    struct perf_record_sample * new_e;
    int ret = 0;
    if (cur + e->header.size > end) {
        int full_size = sizeof(struct perf_record_sample)+ e->header.size;
        new_e = (struct perf_record_sample*)malloc(full_size);

        int rest = end - cur;
        memcpy(new_e, e, rest);
        memcpy((u8*)new_e + rest, (u64*)begin, full_size - rest);

        ret = _perf_process(new_e, h);
        free(new_e);
    } else {
        ret = _perf_process(e, h);
    }
    return ret;
}

static int _perf_commit(const addr_t head, const addr_t tail, 
                        const addr_t begin, const addr_t end,
                        perf_sample_handle_t* h
                        ) {
    int ret = 0;
    addr_t cur = tail;
    while (cur != head) {
        struct perf_event_header *e = (struct perf_event_header *)cur;

        if (e->size == 0) {
            fprintf(stderr, "size is 0, empty\n");
            abort();
        }
        switch (e->type)
        {
// refer to https://lxr.missinglinkelectronics.com/linux+v5.10/include/uapi/linux/perf_event.h#L901
        case PERF_RECORD_LOST_SAMPLES:
            fprintf(stderr, "PERF_RECORD_LOST_SAMPLES\n");
            break;
        case PERF_RECORD_SAMPLE:
            return _perf_sample(begin, end, cur, (struct perf_record_sample *)e, h);
        
        default:
            fprintf(stderr, "no support type %d\n", e->type);
            break;
        }
        cur += e->size;
        if (cur >= end) {
            cur = begin + (cur - end);
        }
    }
    return 0;
}

static int _perf_read(const addr_t addr, perf_sample_handle_t* h) {
    int ret = 0;
    addr_t begin = addr + per_page_size;
    addr_t end  = addr + (NR_PER_RING + 1) * per_page_size;
    struct perf_event_mmap_page *pcp = (struct perf_event_mmap_page *)addr;
    addr_t head = (ACCESS_ONCE(pcp->data_head) & per_map_mask) + begin;
    addr_t tail = (ACCESS_ONCE(pcp->data_tail) & per_map_mask) + begin;
    if (head == tail) {
        return -1;
    }
    ret = _perf_commit(head, tail, begin, end, h);
    mb();
    pcp->data_tail = pcp->data_head;
    return ret;
}

int perf_live_on_read(void *handle) {
    perf_sample_handle_t* h = (perf_sample_handle_t *)handle;
    UT_array * array = h->array;
    int len = utarray_len(array);
    int i;

    for (i = 0; i < len; i ++) {
        perf_sample_cell_t* cell = (perf_sample_cell_t*)utarray_eltptr(array, i);
        addr_t addr = cell->perf_addr;
        _perf_read(addr, h);
    }
}
