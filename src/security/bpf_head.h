//
// Created by qianlu on 2024/6/16.
//

#ifndef SYSAK_BPF_HEAD_H
#define SYSAK_BPF_HEAD_H

extern "C" {
#include "../coolbpf.h"
#include <bpf/libbpf.h>
};

#ifdef COOLBPF_PERF_THREAD

#define DEFINE_SEKL_OBJECT(skel_name)                            \
    struct skel_name##_bpf *skel_name = NULL;                    \
    static pthread_t perf_thread = 0;                            \
    int thread_worker(struct beeQ *q, void *arg)                 \
    {                                                            \
        perf_thread_worker(arg);                                 \
        return 0;                                                \
    }                                                            \
    void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)  \
    {                                                            \
        printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu); \
    }

#define LOAD_SKEL_OBJECT(skel_name, perf)                                                           \
    (                                                                                               \
        {                                                                                           \
            __label__ load_bpf_skel_out;                                                            \
            int __ret = 0;                                                                          \
            skel_name = skel_name##_bpf__open();                                                    \
            if (!skel_name)                                                                         \
            {                                                                                       \
                printf("failed to open BPF object\n");                                              \
                __ret = -1;                                                                         \
                goto load_bpf_skel_out;                                                             \
            }                                                                                       \
            __ret = skel_name##_bpf__load(skel_name);                                               \
            if (__ret)                                                                              \
            {                                                                                       \
                printf("failed to load BPF object: %d\n", __ret);                                   \
                DESTORY_SKEL_BOJECT(skel_name);                                                     \
                goto load_bpf_skel_out;                                                             \
            }                                                                                       \
            struct bpf_program* prog;                                                               \
            prog = bpf_object__find_program_by_name(skel_name->obj, "execve_rate");                 \
            if (prog) {bpf_program__set_autoload(prog, false);                                    \
              printf("execve_rate found and set not to autoattach");                                \
            }                                                                                       \
            else printf("execve_rate not found ");                                                  \
            prog = bpf_object__find_program_by_name(skel_name->obj, "execve_send");                 \
            if (prog) {bpf_program__set_autoload(prog, false);                                    \
              printf("execve_send found and set not to autoattach");                                \
            }                                                                                       \
            else printf("execve_send not found ");                                                  \
            __ret = skel_name##_bpf__attach(skel_name);                                             \
            if (__ret)                                                                              \
            {                                                                                       \
                printf("failed to attach BPF programs: %s\n", strerror(-__ret));                    \
                DESTORY_SKEL_BOJECT(skel_name);                                                     \
                goto load_bpf_skel_out;                                                             \
            }                                                                                       \
            struct perf_thread_arguments *perf_args = calloc(1, sizeof(struct perf_thread_arguments)); \
            if (!perf_args)                                                                         \
            {                                                                                       \
                __ret = -ENOMEM;                                                                    \
                printf("failed to allocate memory: %s\n", strerror(-__ret));                        \
                DESTORY_SKEL_BOJECT(skel_name);                                                     \
                goto load_bpf_skel_out;                                                             \
            }                                                                                       \
            perf_args->mapfd = bpf_map__fd(skel_name->maps.perf);                                   \
            perf_args->sample_cb = handle_event;                                                    \
            perf_args->lost_cb = handle_lost_events;                                                \
            perf_args->ctx = arg;                                                                   \
            perf_thread = beeQ_send_thread(arg, perf_args, thread_worker);                          \
        load_bpf_skel_out:                                                                          \
            __ret;                                                                                  \
        })

#define DESTORY_SKEL_BOJECT(skel_name) \
    if (perf_thread != 0)              \
        plugin_thread_stop(perf_thread); \
    skel_name##_bpf__destroy(skel_name);
#else
#define DEFINE_SEKL_OBJECT(skel_name)                            \
    struct skel_name##_bpf *skel_name = NULL;

#define LOAD_SKEL_OBJECT(skel_name, perf)                                                           \
    (                                                                                               \
        {                                                                                           \
            __label__ load_bpf_skel_out;                                                            \
            int __ret = 0;                                                                          \
            skel_name = skel_name##_bpf__open();                                                    \
            if (!skel_name)                                                                         \
            {                                                                                       \
                printf("failed to open BPF object\n");                                              \
                __ret = -1;                                                                         \
                goto load_bpf_skel_out;                                                             \
            }                                                                                       \
            __ret = skel_name##_bpf__load(skel_name);                                               \
            if (__ret)                                                                              \
            {                                                                                       \
                printf("failed to load BPF object: %d\n", __ret);                                   \
                DESTORY_SKEL_BOJECT(skel_name);                                                     \
                goto load_bpf_skel_out;                                                             \
            }                                                                                       \
            struct bpf_program* prog;                                                               \
            prog = bpf_object__find_program_by_name(skel_name->obj, "execve_rate");                 \
            if (prog) {bpf_program__set_autoload(prog, false);                                    \
              printf("execve_rate found and set not to autoattach\n");                                \
            }                                                                                       \
            else printf("execve_rate not found ");                                                  \
            prog = bpf_object__find_program_by_name(skel_name->obj, "execve_send");                 \
            if (prog) {bpf_program__set_autoload(prog, false);                                    \
              printf("execve_send found and set not to autoattach\n");                                \
            }                                                                                       \
            else printf("execve_send not found ");                                                  \
            __ret = skel_name##_bpf__attach(skel_name);                                             \
            if (__ret)                                                                              \
            {                                                                                       \
                printf("failed to attach BPF programs: %s\n", strerror(-__ret));                    \
                DESTORY_SKEL_BOJECT(skel_name);                                                     \
                goto load_bpf_skel_out;                                                             \
            }                                                                                       \
        load_bpf_skel_out:                                                                          \
            __ret;                                                                                  \
        })

#define DESTORY_SKEL_BOJECT(skel_name) \
    skel_name##_bpf__destroy(skel_name);
#endif

#define coobpf_map_find(OBJ, NAME) bpf_object__find_map_fd_by_name(OBJ, NAME)
#define coobpf_key_next(FD, KEY, NEXT) bpf_map_get_next_key(FD, KEY, NEXT)
#define coobpf_key_value(FD, KEY, VALUE) bpf_map_lookup_elem(FD, KEY, VALUE)



#endif //SYSAK_BPF_HEAD_H
