#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <netdb.h>
#include <signal.h>

#include <linux/bpf.h>
#include <sys/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_rlimit.h"
#include "bpf_util.h"
#include "cgroup_helpers.h"

#include "sockops_kern.h"

struct sock_key {
	uint32_t sip4;
	uint32_t dip4;
	uint8_t family;
	uint8_t pad1;
	uint16_t pad2;
	uint32_t pad3;
	uint32_t sport;
	uint32_t dport;
} __attribute__((packed));

static int hash_fd;
static int progs_fd[2];

static void hup_handler(int a)
{
	printf("sighup recv");
}

static int bpf_find_map(const char *test, struct bpf_object *obj, const char *name)
{
	struct bpf_map *map;

	map = bpf_object__find_map_by_name(obj, name);
	if (!map) {
		printf("%s:FAIL:map '%s' not found\n", test, name);
		return -1;
	}
	return bpf_map__fd(map);
}

static int get_peer(struct sock_key *orig, struct sock_key *peer)
{
	peer->dip4 = orig->sip4;
	peer->sip4 = orig->dip4;
	peer->family = 1;
	peer->dport = orig->sport;
	peer->sport = orig->dport;
}

int main(int argc, char **argv)
{
	const char *cg_path = "/test";
	int cg_fd = -1;
	int hash_fd = -1;
	int peer_fd = -1;

	int err;
	long long value, peer_value, max;
	struct sock_key key, next_key, peer_key;
	struct timespec curr_ns;

	struct sockops_kern *skel = sockops_kern__open_and_load();
	if (!skel) {
		printf("ERROR: skeleton open/load failed");
		return;
	}

	cg_fd = cgroup_setup_and_join(cg_path);
	if (cg_fd < 0)
		goto err;

	hash_fd = bpf_map__fd(skel->maps.sock_ops_map);
	peer_fd = bpf_map__fd(skel->maps.peer_stamp);

	progs_fd[0] = bpf_program__fd(skel->progs.bpf_sockops_func);
	err = bpf_prog_attach(progs_fd[0], cg_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (err) {
		printf("FAILED:  bpf_prog_attach cgroup:%d,  %d (%s)\n", progs_fd[0], err, strerror(errno));
		goto err;
	}

	progs_fd[1] = bpf_program__fd(skel->progs.bpf_skmsg_func);
	err = bpf_prog_attach(progs_fd[1], hash_fd, BPF_SK_MSG_VERDICT, 0);
	if (err) {
		printf("ERROR: bpf_prog_attach sk_msg,fd:%d,%d , %d (%s)\n", progs_fd[1], hash_fd, err, strerror(errno));
		goto err;
	}

	signal(SIGHUP, hup_handler);

	printf("main loop\n");
	while (1) {
		sleep(1);	//s
		memset(&key, 0, sizeof(struct sock_key));
		while (!bpf_map_get_next_key(peer_fd, &key, &next_key)) {
			get_peer(&next_key, &peer_key);

			bpf_map_lookup_elem(peer_fd, &next_key, &value);
			bpf_map_lookup_elem(peer_fd, &peer_key, &peer_value);
			clock_gettime(CLOCK_MONOTONIC, &curr_ns);
			if (peer_value > value) {
				printf("%d->%d:delay at %lu from %lu\n", peer_key.sport, peer_key.dport, curr_ns.tv_sec, peer_value / 1000000000);
			} else {
				printf("%d->%d:delay at %lu from %lu\n", next_key.sport, next_key.dport, curr_ns.tv_sec, value / 1000000000);
			}

			key = next_key;
		}
	}
      err:
	bpf_prog_detach(cg_fd, BPF_CGROUP_SOCK_OPS);
	close(cg_fd);
	cleanup_cgroup_environment();
	return err;
}
