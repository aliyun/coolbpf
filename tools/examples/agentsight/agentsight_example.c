/*
 * AgentSight C Example — eventfd + epoll mode
 *
 * Demonstrates how to use the AgentSight C FFI API to observe LLM agent
 * behavior via eBPF.  Requires root (CAP_BPF + CAP_SYS_ADMIN) to attach
 * eBPF probes.
 *
 * Build:
 *   gcc -o agentsight_example agentsight_example.c \
 *       -I/path/to/agentsight/include \
 *       -L/path/to/agentsight/lib \
 *       -lagentsight
 *
 * Run:
 *   sudo LD_LIBRARY_PATH=/path/to/agentsight/lib ./agentsight_example
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "agentsight.h"

/* ── Global flag for clean shutdown ──────────────────────────────────── */

static volatile sig_atomic_t g_running = 1;

static void sig_handler(int sig) {
    (void)sig;
    g_running = 0;
}

/* ── Callbacks ───────────────────────────────────────────────────────── */

static void on_https_event(const AgentsightHttpsData *data, void *user_data) {
    (void)user_data;
    printf("[HTTPS] pid=%d comm=%.15s %s %s status=%u dur=%luus\n",
           data->pid, data->process_name,
           data->method, data->path,
           data->status_code,
           data->duration_ns / 1000);

    if (data->is_sse) {
        printf("       (SSE stream)\n");
    }

    if (data->response_body && data->response_body_len > 0) {
        /* Print a truncated preview of the response body */
        uint32_t preview_len = data->response_body_len > 200
                               ? 200 : data->response_body_len;
        printf("       body(%u): %.*s\n",
               data->response_body_len, (int)preview_len, data->response_body);
    }
}

static void on_llm_event(const AgentsightLLMData *data, void *user_data) {
    (void)user_data;
    printf("[LLM]   pid=%d comm=%.15s agent=%s provider=%s model=%s\n",
           data->pid, data->process_name,
           data->agent_name ? data->agent_name : "(null)",
           data->provider, data->model);
    printf("       url=%s status=%u finish=%s sse=%u dur=%luus\n",
           data->request_url, data->status_code,
           data->finish_reason ? data->finish_reason : "(null)",
           data->is_sse,
           data->duration_ns / 1000);
    printf("       tokens: in=%u out=%u total=%u (source=%s)\n",
           data->input_tokens, data->output_tokens, data->total_tokens,
           data->llm_usage ? "api" : "local");

    if (data->cache_creation_input_tokens || data->cache_read_input_tokens) {
        printf("       cache: creation=%u read=%u\n",
               data->cache_creation_input_tokens,
               data->cache_read_input_tokens);
    }

    if (data->response_messages && data->response_messages_len > 0) {
        uint32_t preview_len = data->response_messages_len > 200
                               ? 200 : data->response_messages_len;
        printf("       resp(%u): %.*s\n",
               data->response_messages_len, (int)preview_len,
               data->response_messages);
    }

    printf("\n");
}

/* ── Main ────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    int opt_verbose = 0;
    const char *log_path = NULL;

    /* Parse options */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            opt_verbose = 1;
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            log_path = argv[++i];
        } else {
            fprintf(stderr,
                    "Usage: %s [-v|--verbose] [--log <path>]\n"
                    "\n"
                    "  -v, --verbose   Enable AgentSight debug logging\n"
                    "  --log <path>    Write logs to file instead of stderr\n",
                    argv[0]);
            return strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0
                   ? 0 : 1;
        }
    }

    /* Install signal handlers for graceful shutdown */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Print version */
    printf("AgentSight version: %s\n", agentsight_version());
    printf("Press Ctrl+C to stop.\n\n");

    /* ── Configuration ─────────────────────────────────────────────── */
    AgentsightConfigHandle *cfg = agentsight_config_new();
    if (!cfg) {
        fprintf(stderr, "Failed to create config\n");
        return 1;
    }
    if (opt_verbose) {
        agentsight_config_set_verbose(cfg, 1);
    }
    if (log_path) {
        agentsight_config_set_log_path(cfg, log_path);
    }

    /* ── Create handle ─────────────────────────────────────────────── */
    AgentsightHandle *h = agentsight_new(cfg);
    agentsight_config_free(cfg); /* new() copies config; free the original */

    if (!h) {
        fprintf(stderr, "agentsight_new failed: %s\n", agentsight_last_error());
        return 1;
    }

    /* ── Start eBPF pipeline ───────────────────────────────────────── */
    if (agentsight_start(h) < 0) {
        fprintf(stderr, "agentsight_start failed: %s\n", agentsight_last_error());
        agentsight_free(h);
        return 1;
    }

    /* ── Set up eventfd + epoll ────────────────────────────────────── */
    int as_efd = agentsight_get_eventfd(h);
    if (as_efd < 0) {
        fprintf(stderr, "eventfd not available, falling back to polling\n");

        /* Polling fallback */
        while (g_running) {
            agentsight_read(h,
                            on_https_event, NULL,
                            on_llm_event, NULL,
                            0 /* non-blocking */);
            usleep(100000); /* 100 ms */
        }
    } else {
        /* eventfd + epoll mode (recommended) */
        int epoll_fd = epoll_create1(0);
        if (epoll_fd < 0) {
            perror("epoll_create1");
            agentsight_stop(h);
            agentsight_free(h);
            return 1;
        }

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events  = EPOLLIN;
        ev.data.fd = as_efd;   /* identify AgentSight events by fd */

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, as_efd, &ev) < 0) {
            perror("epoll_ctl ADD");
            close(epoll_fd);
            agentsight_stop(h);
            agentsight_free(h);
            return 1;
        }

        /* ── Event loop ───────────────────────────────────────────── */
        while (g_running) {
            struct epoll_event events[16];
            int n = epoll_wait(epoll_fd, events, 16, 500 /* ms */);

            for (int i = 0; i < n; i++) {
                if (events[i].data.fd == as_efd) {
                    /* AgentSight has events ready — non-blocking consume */
                    agentsight_read(h,
                                    on_https_event, NULL,
                                    on_llm_event, NULL,
                                    0 /* non-blocking */);
                }
            }
        }

        /* ── Cleanup ───────────────────────────────────────────────── */
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, as_efd, NULL);
        close(epoll_fd);
    }

    printf("\nShutting down...\n");
    agentsight_stop(h);
    agentsight_free(h);  /* also closes as_efd internally */

    printf("Done.\n");
    return 0;
}
