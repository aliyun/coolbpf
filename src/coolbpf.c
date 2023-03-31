/**
 * @file coolbpf.c
 * @author Shuyi Cheng (chengshuyi@linux.alibaba.com)
 * @brief
 * @version 0.1
 * @date 2022-12-22
 *
 * @copyright Copyright (c) 2022
 *
 */

#ifdef __VMLINUX_H__

#else

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <asm/unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/resource.h>

#include "coolbpf.h"
uint32_t coolbpf_major_version(void)
{
    return COOLBPF_MAJOR_VERSION;
}

uint32_t coolbpf_minor_version(void)
{
    return COOLBPF_MINOR_VERSION;
}

const char *coolbpf_version_string(void)
{
#define __S(X) #X
#define _S(X) __S(X)
    return "v" _S(COOLBPF_MAJOR_VERSION) "." _S(COOLBPF_MINOR_VERSION);
#undef _S
#undef __S
}

int coolbpf_object_load(struct coolbpf_object *cb)
{
    int err = 0;
    if (cb->preload)
        err = cb->preload(cb->ctx, cb->skel_obj);
    err = err ?: cb->skel_load(cb->skel_obj);
    return err;
}

int coolbpf_object_attach(struct coolbpf_object *cb)
{
    int err = 0;
    if (cb->preattach)
        err = cb->preattach(cb->ctx, cb->skel_obj);
    err = err ?: cb->skel_attach(cb->skel_obj);
    return err;
}

void coolbpf_object_destroy(struct coolbpf_object *cb)
{
    cb->skel_destroy(cb->skel_obj);
}

int coolbpf_object_find_map(struct coolbpf_object *cb, const char *name)
{
    return bpf_object__find_map_fd_by_name(coolbpf_get_bpf_object(cb), name);
}

const struct bpf_object *coolbpf_get_bpf_object(struct coolbpf_object *cb)
{
    return (const struct bpf_object *)(((uint64_t *)cb->skel_obj)[1]);
}

int coolbpf_create_perf_thread(struct coolbpf_object *cb, const char *perfmap_name)
{
    return 0;
}


void *perf_thread_worker(void *ctx)
{
    int err;
    struct perf_buffer *pb = NULL;
    struct perf_buffer_opts pb_opts = {};
    struct perf_thread_arguments *args = (struct perf_thread_arguments *)ctx;
    int timeout_ms = args->timeout_ms == 0 ? 100 : args->timeout_ms;

    pb_opts.sample_cb = args->sample_cb;
    pb_opts.ctx = args->ctx;
    pb_opts.lost_cb = args->lost_cb;
    pb = perf_buffer__new(args->mapfd, args->pg_cnt == 0 ? 128 : args->pg_cnt, &pb_opts);
    free(args);

    err = libbpf_get_error(pb);
    if (err)
    {
        error("error new perf buffer: %s\n", strerror(-err));
        return NULL;
    }

    if (!pb)
    {
        err = -errno;
        error("failed to open perf buffer: %d\n", err);
        return NULL;
    }

    while (true)
    {
        err = perf_buffer__poll(pb, timeout_ms);
        if (err < 0 && err != -EINTR)
        {
            error("error polling perf buffer: %s\n", strerror(-err));
            goto cleanup;
        }

        if (err == -EINTR)
            goto cleanup;
        /* reset err to return 0 if exiting */
        err = 0;
    }
cleanup:
    perf_buffer__free(pb);
    return NULL;
}

pthread_t initial_perf_thread(struct perf_thread_arguments *args)
{
    pthread_t thread;
    struct perf_thread_arguments *args_copy = malloc(sizeof(struct perf_thread_arguments));
    if (!args_copy)
        return -ENOMEM;

    memcpy(args_copy, args, sizeof(struct perf_thread_arguments));
    pthread_create(&thread, NULL, perf_thread_worker, args);
    return thread;
}

int kill_perf_thread(pthread_t thread)
{
    pthread_kill(thread, SIGQUIT);
    pthread_join(thread, NULL);
    return 0;
}

int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}
#endif
