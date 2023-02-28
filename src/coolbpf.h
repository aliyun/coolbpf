/**
 * @file coolbpf.h
 * @author Shuyi Cheng (chengshuyi@linux.alibaba.com)
 * @brief
 * @version 0.1
 * @date 2022-12-22
 *
 * @copyright Copyright (c) 2022
 *
 */
#ifndef __COOLBPF_H
#define __COOLBPF_H

#ifdef __VMLINUX_H__

#include "coolbpf_bpf.h"

#else

#define COOLBPF_MAJOR_VERSION 1
#define COOLBPF_MINOR_VERSION 0

#include "coolbpf_common.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pthread.h>

typedef int (*pre_load)(void *ctx, void *skel_object);
typedef int (*pre_attach)(void *ctx, void *skel_object);

/**
 * @brief coolbpf object
 *
 */
struct coolbpf_object
{
    int (*skel_load)(void *skel);     /**< function callback to load eBPF skeleton */
    int (*skel_attach)(void *skel);   /**< function callback to attach eBPF skeleton */
    void (*skel_destory)(void *skel); /**< function callback to destory eBPF skeleton */
    void *skel;                       /**< instance of skeleton object */
    pre_load preload;                 /**< function callback before load eBPF skeleton */
    pre_attach preattach;             /**< function callback before attach eBPF skeleton */
    void *ctx;                        /**< user's private context */
};

#define __coolbpf_object_new(skel, preload, preattach, ctx)                       \
    (                                                                             \
        {                                                                         \
            skel##_bpf *skel_obj = skel##_bpf__open();                            \
            int __err = 0;                                                        \
            if (!skel_obj)                                                        \
                return NULL;                                                      \
            struct coolbpf_object *cb = calloc(1, sizeof(struct coolbpf_object)); \
            if (!cb)                                                              \
                return NULL;                                                      \
            cb->load = skel##_bpf__load;                                          \
            cb->attach = skel##_bpf__attach;                                      \
            cb->destory = skel##_bpf__desotry;                                    \
            cb->skel = skel_obj;                                                  \
            cb->preload = preload;                                                \
            cb->preattach = preattach;                                            \
            cb->ctx = ctx;                                                        \
            __err = coolbpf_object_load(cb);                                      \
            if (__err)                                                            \
            {                                                                     \
                printf("failed to load BPF object: %d\n", __err);                 \
                coolbpf_object_destory(cb);                                       \
                return NULL;                                                      \
            }                                                                     \
            __err = coolbpf_object_attach(cb);                                    \
            if (__err)                                                            \
            {                                                                     \
                printf("failed to attach BPF object: %d\n", __err);               \
                coolbpf_object_destory(cb);                                       \
                return NULL;                                                      \
            }                                                                     \
            cb;                                                                   \
        })

#define coolbpf_object_new(skel) \
    __coolbpf_object_new(skel, NULL, NULL, NULL)

#define coolbpf_object_new_with_prehandler(skel, preload, preattach, ctx) \
    __coolbpf_object_new(skel, preload, preattach, ctx)

/**
 * @brief load coolbpf object
 *
 * @param cb
 * @return int
 */
COOLBPF_API int coolbpf_object_load(struct coolbpf_object *cb);

/**
 * @brief attach coolbpf object
 *
 * @param cb
 * @return int
 */
COOLBPF_API int coolbpf_object_attach(struct coolbpf_object *cb);

/**
 * @brief destory coolbpf object instance
 *
 * @param cb
 */
COOLBPF_API void coolbpf_object_destory(struct coolbpf_object *cb);

/**
 * @brief get bpf map fd from coolbpf object
 *
 * @param cb
 * @param name
 * @return int
 */
COOLBPF_API int coolbpf_object_find_map(struct coolbpf_object *cb, const char *name);

/**
 * @brief get bpf_object instance
 *
 * @param cb
 * @return const struct bpf_object*
 */
COOLBPF_API const struct bpf_object *coolbpf_get_bpf_object(struct coolbpf_object *cb);



COOLBPF_API int coolbpf_create_perf_thread(struct coolbpf_object *cb, const char *perfmap_name);

/**
 * @brief Parameters required to create perf threads
 *
 */
struct perf_thread_arguments
{
    int mapfd;                       /**< fd of perf event map */
    perf_buffer_sample_fn sample_cb; /**< callback function */
    perf_buffer_lost_fn lost_cb;     /**< callback function when the event is lost */
    int pg_cnt;                      /**< perf buffer size in page, default is 128 page */
    int timeout_ms;                  /**< timeout of perf poll in ms, default is 100ms */
    void *ctx;                       /**< perf_buffer_sample_fn and perf_buffer_lost_fn context */
};

/**
 * @brief get coolbpf major verison
 *
 * @return uint32_t
 */
COOLBPF_API uint32_t coolbpf_major_version();

/**
 * @brief get coolbpf minor version
 *
 * @return uint32_t
 */
COOLBPF_API uint32_t coolbpf_minor_version();

/**
 * @brief get coolbpf version as string
 *
 * @return const char*
 */
COOLBPF_API const char *coolbpf_version_string(void);

/**
 * @brief perf thread worker
 *
 * @param ctx perf thread arguments
 * @return void *
 */
COOLBPF_API void *perf_thread_worker(void *ctx);

/**
 * @brief Create a perf thread to receive perf events
 *
 * @param mapfd fd of map of type BPF_MAP_TYPE_PERF_EVENT_ARRAY
 * @return pthread_t thread id, you can use it later to destroy the thread
 */
COOLBPF_API pthread_t initial_perf_thread(struct perf_thread_arguments *args);

/**
 * @brief Destroy perf thread
 *
 * @param thread perf thread id
 * @return int
 */
COOLBPF_API int kill_perf_thread(pthread_t thread);

/**
 * @brief Extend locked-in-memory address space
 *
 * @return int
 */
int bump_memlock_rlimit(void);

#endif

#endif
