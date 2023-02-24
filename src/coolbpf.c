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
    if (err) {
        fprintf(stderr, "error new perf buffer: %s\n", strerror(-err));
        return NULL;
    }
    
    if (!pb)
    {
        err = -errno;
        fprintf(stderr, "failed to open perf buffer: %d\n", err);
        return NULL;
    }

    while (true)
    {
        err = perf_buffer__poll(pb, timeout_ms);
        if (err < 0 && err != -EINTR)
        {
            fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
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
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}
#endif
