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
#include <sys/types.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_rlimit.h"
#include "bpf_util.h"
#include "cgroup_helpers.h"

#include "proxy_kern.h"

static int sockmap_fd, proxymap_fd;
static int progs_fd[4];

static int ctrl = 1;

// start proxy and echo server
#define BUFFER_SIZE 1024
#define on_error(...)                 \
    {                                 \
        fprintf(stderr, __VA_ARGS__); \
        perror("cause by");           \
        fflush(stderr);               \
        exit(1);                      \
    }

static int proxysd1, proxysd2;
static int echoport1 = 9001;
static int echoport2 = 9002;
static int proxyport = 9000;
static int max_entries = 1024;

typedef void (*thread_func_ptr)(int, int, int);

void proxy_app(int client_fd, int listen_port, int client_remote_port)
{
	int read_bytes;
	int write_bytes;
	int upstream;
	char buff[BUFFER_SIZE];
	char pbuff[BUFFER_SIZE];

	srand(time(0));
	if (rand() % 2 == 1) {
		upstream = proxysd1;
	} else {
		upstream = proxysd2;
	}

	do {
		bzero(buff, BUFFER_SIZE);
		bzero(pbuff, BUFFER_SIZE);
		read_bytes = recv(client_fd, buff, BUFFER_SIZE, 0);
		if (read_bytes <= 0) {
			printf("PROXY FAILED to read fd %d(accept at %d) from remote port %d\n", client_fd, listen_port, client_remote_port);
			break;
		}
		printf("PROXY read fd %d(accept at %d) from remote port %d:%s\n", client_fd, listen_port, client_remote_port, buff);

		write_bytes = send(upstream, buff, read_bytes, 0);
		if (write_bytes < 0) {
			printf("PROXY failed to write to echoserver fd %d\n", upstream);
			break;
		}
		printf("PROXY write upstream fd %d:%s\n", upstream, buff);

		read_bytes = recv(upstream, pbuff, BUFFER_SIZE, 0);
		if (read_bytes <= 0) {
			printf("PROXY FAILED to read upstream fd %d\n", upstream);
			break;
		}
		printf("PROXY read upstream fd %d:%s\n", upstream, pbuff);

		write_bytes = send(client_fd, pbuff, read_bytes, 0);
		if (write_bytes < 0) {
			printf("PROXY FAILED to write fd %d(accept at %d) from remote port %d\n", client_fd, listen_port, client_remote_port);
			break;
		}
		printf("PROXY write fd %d(accept at %d) from remote port %d:%s\n", client_fd, listen_port, client_remote_port, pbuff);
	} while (strncmp(buff, "bye\r", 4) != 0);

	printf("PROXY connection closed fd %d(accept at %d) from remote port %d\n", client_fd, listen_port, client_remote_port);
	return;
}

void proxy_bpf(int client_fd, int listen_port, int client_remote_port)
{
	int err;
	int key;

	for (key = 0; key < max_entries; key++) {
		err = bpf_map_delete_elem(proxymap_fd, &key);
		if (err && errno != EINVAL && errno != ENOENT)
			printf("map_delete: expected EINVAL/ENOENT");
	}

	key = 0;
	bpf_map_update_elem(sockmap_fd, &key, &client_fd, BPF_NOEXIST);

	key = 1;
	bpf_map_update_elem(sockmap_fd, &key, &proxysd1, BPF_NOEXIST);

	key = 2;
	bpf_map_update_elem(sockmap_fd, &key, &proxysd2, BPF_NOEXIST);

	unsigned short key16 = 0;
	key16 = client_remote_port;
	int val = 1;
	bpf_map_update_elem(proxymap_fd, &key16, &val, BPF_ANY);
	printf("MARK client port:%d\n", key16);

	key16 = echoport1;
	val = 2;
	bpf_map_update_elem(proxymap_fd, &key16, &val, BPF_ANY);
	printf("MARK upstream port :%d\n", key16);

	key16 = echoport2;
	val = 2;
	bpf_map_update_elem(proxymap_fd, &key16, &val, BPF_ANY);
	printf("MARK upstream port :%d\n", key16);
}

void proxy(int client_fd, int listen_port, int client_remote_port)
{
	proxy_init();

	if (ctrl == 2) {
		proxy_bpf(client_fd, listen_port, client_remote_port);
	}

	proxy_app(client_fd, listen_port, client_remote_port);

	close(client_fd);
	close(proxysd1);
	close(proxysd2);
}

void proxy_init()
{
	struct sockaddr_in proxyaddr1, proxyaddr2;

	proxysd1 = socket(AF_INET, SOCK_STREAM, 0);
	proxysd2 = socket(AF_INET, SOCK_STREAM, 0);

	bzero(&proxyaddr1, sizeof(struct sockaddr_in));
	proxyaddr1.sin_family = AF_INET;
	proxyaddr1.sin_port = htons(echoport1);
	proxyaddr1.sin_addr.s_addr = inet_addr("127.0.0.1");

	bzero(&proxyaddr2, sizeof(struct sockaddr_in));
	proxyaddr2.sin_family = AF_INET;
	proxyaddr2.sin_port = htons(echoport2);
	proxyaddr2.sin_addr.s_addr = inet_addr("127.0.0.1");

	connect(proxysd1, (struct sockaddr *)&proxyaddr1, sizeof(struct sockaddr));
	connect(proxysd2, (struct sockaddr *)&proxyaddr2, sizeof(struct sockaddr));
}

void echo(int client_fd, int listen_port, int client_remote_port)
{
	char buff[BUFFER_SIZE];
	int write_bytes = 0;
	int read_bytes = 0;
	do {
		bzero(buff, BUFFER_SIZE);
		read_bytes = recv(client_fd, buff, BUFFER_SIZE, 0);
		if (read_bytes <= 0) {
			printf("ECHO  FAILED to read fd %d(accept at %d) from remote port %d\n", client_fd, listen_port, client_remote_port);
			break;
		}
		printf("ECHO  read at fd %d(accept at %d) from remote port %d:%s\n", client_fd, listen_port, client_remote_port, buff);

		if (listen_port % 2 == 1) {
			buff[0] = 'A';
		} else {
			buff[0] = 'B';
		}

		write_bytes = send(client_fd, buff, read_bytes, 0);
		if (write_bytes < 0) {
			printf("ECHO  FAILED to write fd %d(accept at %d) from remote port %d\n", client_fd, listen_port, client_remote_port);
			break;
		}
		printf("ECHO  write to fd %d(accept at %d) from remote port %d:%s\n", client_fd, listen_port, client_remote_port, buff);

	} while (strncmp(buff, "bye\r", 4) != 0);

	printf("ECHO  connection closed fd %d(accept at %d) from remote port %d\n", client_fd, listen_port, client_remote_port);
	close(client_fd);
}

int thread_server(int *serverport, thread_func_ptr call)
{
	int opt_val = 1;
	int server_fd, client_fd;
	struct sockaddr_in serveraddr, clientaddr;
	socklen_t client_len = sizeof(clientaddr);

	server_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (server_fd < 0)
		on_error("Could not create socket\n");

	bzero((char *)&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(*serverport);
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof opt_val);

	if (bind(server_fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
		on_error("Could not bind socket\n");

	if (listen(server_fd, 16) < 0)
		on_error("Could not listen on socket\n");

	printf("Server %d is listening on %d\n", (int)gettid(), *serverport);

	while (1) {
		client_fd = accept(server_fd, (struct sockaddr *)&clientaddr, &client_len);
		if (client_fd < 0)
			on_error("Could not establish new connection\n");

		printf("Connected from: %s:%d, file descriptor: %d\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port), client_fd);

		if (call)
			call(client_fd, *serverport, ntohs(clientaddr.sin_port));
	}

	return 0;
}

int echo_server(int *serverport)
{
	return thread_server(serverport, &echo);
}

int proxy_server(int *serverport)
{
	return thread_server(serverport, &proxy);
}

void start()
{
	pthread_t child_tid1;
	if (pthread_create(&child_tid1, NULL, echo_server, &echoport1) == 0)
		pthread_detach(child_tid1);
	else
		perror("Thread create failed");

	pthread_t child_tid2;
	if (pthread_create(&child_tid2, NULL, echo_server, &echoport2) == 0)
		pthread_detach(child_tid2);
	else
		perror("Thread create failed");

	sleep(1);		//s

	pthread_t child_tid3;
	if (pthread_create(&child_tid3, NULL, proxy_server, &proxyport) == 0)
		pthread_detach(child_tid3);
	else
		perror("Thread create failed");
}

// end proxy and echo server

///////////////////////////////////////////////////////////////

static void hup_handler(int a)
{
	int key;
	printf("sighup recv and ");
	if (ctrl == 1) {
		printf("START bpf redirect skb\n");
		ctrl = 2;
	} else if (ctrl == 2) {
		printf("STOP bpf redirect skb\n");
		ctrl = 1;

		key = 0;
		bpf_map_delete_elem(sockmap_fd, &key);

		key = 1;
		bpf_map_delete_elem(sockmap_fd, &key);

		key = 2;
		bpf_map_delete_elem(sockmap_fd, &key);
	}
}

int main(int argc, char **argv)
{
	const char *cg_path = "/proxy_test";
	int cg_fd = -1;
	int err;

	struct proxy_kern *skel = proxy_kern__open_and_load();
	if (!skel) {
		printf("ERROR: skeleton open/load failed");
		return;
	}

	cg_fd = cgroup_setup_and_join(cg_path);
	if (cg_fd < 0)
		goto err;

	sockmap_fd = bpf_map__fd(skel->maps.sock_map);
	proxymap_fd = bpf_map__fd(skel->maps.proxy_map);

	progs_fd[0] = bpf_program__fd(skel->progs.bpf_skb_parser);
	err = bpf_prog_attach(progs_fd[0], sockmap_fd, BPF_SK_SKB_STREAM_PARSER, 0);
	if (err) {
		printf("ERROR: bpf_prog_attach parser: %d (%s)\n", err, strerror(errno));
		goto err;
	}

	progs_fd[1] = bpf_program__fd(skel->progs.bpf_skb_verdict);
	err = bpf_prog_attach(progs_fd[1], sockmap_fd, BPF_SK_SKB_STREAM_VERDICT, 0);
	if (err) {
		printf("ERROR: bpf_prog_attach verdict: %d (%s)\n", err, strerror(errno));
		goto err;
	}

	start();
	signal(SIGHUP, hup_handler);

	printf("main loop\n");
	while (1) {
		sleep(1);
	}

      err:
	bpf_prog_detach(cg_fd, BPF_CGROUP_SOCK_OPS);
	close(cg_fd);
	cleanup_cgroup_environment();
	return err;
}
