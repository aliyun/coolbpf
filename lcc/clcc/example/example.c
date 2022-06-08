#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <argp.h>
#include <arpa/inet.h>
#include <stdint.h>

#include "example.h"
#include "example.skel.h"

const char *argp_program_version = "Specify your program version";
const char *argp_program_bug_address = "The address to report bug about your program";
static const char argp_program_doc[] =
    "\nDescription your program\n"
    "\n"
    "EXAMPLES:\n"
    "   first exampe    # add some comment\n"
    "   second exampe   # add some comment\n"
    "   ......                            \n";

static const struct argp_option netinfo_options[] = {
    {"btf", 'b', "BTF_PATH", 0, "Specify path of the custom btf"},
    {"debug", 'd', NULL, 0, "Enable libbpf debug output"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};

static struct env
{
    bool debug;
    char *btf_custom_path;
} env = {
    .debug = false,
    .btf_custom_path = NULL,
};

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (!env.debug)
        return 0;
    return vfprintf(stderr, format, args);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{

    switch (key)
    {
    case 'd':
        env.debug = true;
        break;
    case 'b':
        env.btf_custom_path = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    struct example *ep = data;
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ep->saddr, sip, 16);
    inet_ntop(AF_INET, &ep->daddr, dip, 16);
    printf("(PID)%d:%s   (LOCAL)%s:%u -> (REMOTE)%s:%u\n", ep->pid, ep->comm, sip, ep->sport, dip, ep->dport);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

void event_printer(int perf_map_fd)
{
    struct perf_buffer_opts pb_opts = {
        .sample_cb = handle_event,
        .lost_cb = handle_lost_events,
    };
    struct perf_buffer *pb = NULL;
    int err;

    pb = perf_buffer__new(perf_map_fd, 128, &pb_opts);
    err = libbpf_get_error(pb);
    if (err)
    {
        pb = NULL;
        printf("failed to open perf buffer: %d\n", err);
        goto cleanup;
    }
    while (1)
    {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && errno != EINTR)
        {
            printf("Error polling perf buffer: %d\n", err);
            goto cleanup;
        }
    }
cleanup:
    perf_buffer__free(pb);
}

int main(int argc, char **argv)
{
    struct example_bpf *obj;
    int err;
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    static const struct argp argp = {
        .options = netinfo_options,
        .parser = parse_arg,
        .doc = argp_program_doc,
        .args_doc = NULL,
    };

    bump_memlock_rlimit();
    libbpf_set_print(libbpf_print_fn);
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    open_opts.btf_custom_path = env.btf_custom_path;
    obj = example_bpf__open_opts(&open_opts);
    if (!obj)
    {
        printf("failed to open BPF object\n");
        return 1;
    }
    err = example_bpf__load(obj);
    if (err)
    {
        printf("failed to load BPF object: %d\n", err);
        goto cleanup;
    }
    err = example_bpf__attach(obj);
    if (err)
    {
        printf("failed to attach BPF programs: %s\n", strerror(-err));
        goto cleanup;
    }
    event_printer(bpf_map__fd(obj->maps.events));
cleanup:
    // destory the bpf program
    example_bpf__destroy(obj);
    return 0;
}