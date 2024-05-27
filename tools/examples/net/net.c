/*
 * Author: Chen Tao
 * Create: Sun Feb 20 20:33:51 2022
 */
// #include "syscall.h"
#define _GNU_SOURCE
#include "dlfcn.h"
#include "string.h"
#include "stdio.h"
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include "net.h"
#include <signal.h>
#include <getopt.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
/*
 * test result:
 *
 * net init end...
 * success to update map for tgid: -1
 * success to update map for protocol: 1
 * net config end...
 * net start end...
 * fuc:1(sys_enter_connect), 0.0.0.0:0-> 127.0.0.1:54046: size = 0, com_name:client, pid: 93416, fd:3, family:2, ret_val:0
 * fuc:1(sys_enter_connect), 0.0.0.0:0-> 127.0.0.1:54046: size = 0, com_name:client, pid: 93462, fd:3, family:2, ret_val:0
 * fuc:3(sys_enter_accept), 0.0.0.0:0-> 0.0.0.0:0: size = 0, com_name:server, pid: 93521, fd:3, family:2236, ret_val:0)))
 */

#define MAX_PROTOCOL_NUM 5
struct map_syscall_t *net_mapsys = NULL;
extern struct mproto_t net_mproto[MAX_PROTOCOL_NUM];
int map_fd;

int send_self_packet(int num);
static void test_update_conn_addr(void);
static void test_disable_process(bool drop);

const char *dll_path = "./libbpfnet.so";
bool exiting = false;

struct env_para_t
{
	int proto;
	int pid;
	int self_pid;
	int port;
	int data_sample;
	int ctrl_count;
	int data_count;
	int stat_count;
	int debug;
	FILE *file;
};

struct env_para_t env_para = {
	.proto = -1,
	.pid = -1,
	.self_pid = -1,
	.port = -1,
	.data_sample = -1,
	.ctrl_count = 0,
	.data_count = 0,
	.stat_count = 0,
	.debug = 1,
	.file = NULL,
};

enum libbpf_print_level
{
	DEBUG = 0,
	WARN,
	INFO,
	ERROR,
	MAX,
};
int data_count = 0;
int ctrl_count = 0;
int stat_count = 0;

static void set_ebpf_int_config(int32_t opt, int32_t value)
{
	int32_t *params[] = {&value};
	int32_t paramsLen[] = {4};
	ebpf_config(opt, 0, 1, (void **)params, paramsLen);
}

static int test_print_func(enum libbpf_print_level level,
						   const char *format, va_list args)
{
	int ret;
	if (env_para.debug)
	{
		ret = vfprintf(stderr, format, args);
	}
	return ret;
}

static void test_print(enum libbpf_print_level level,
					   const char *format, ...)
{
	va_list args;

	va_start(args, format);
	test_print_func(level, format, args);
	va_end(args);
}

#ifdef NET_TEST
static void test_process_func(void *custom_data, struct test_data *event_data)
{
	struct test_data *nd = (struct test_data *)event_data;
	char print_buf[1024];
	char sip[20];
	char dip[20];
	int i;

	inet_ntop(AF_INET, &nd->ap.saddr, sip, 16);
	inet_ntop(AF_INET, &nd->ap.daddr, dip, 16);
	char func[30];
	strncpy(func, net_mapsys[nd->funcid].funcname, 30);
	// printf("test_process:%s\n", nd->com);
	if (!strncmp(nd->com, "client", strlen("client")) ||
		!strncmp(nd->com, "server", strlen("server")))
	{
		printf("fuc:%d(%s), %s:%u-> %s:%u: size = %u, com_name:%s, pid: %d, fd:%d, family:%d, ret_val:%d\n",
			   nd->funcid, func, sip, nd->ap.sport, dip,
			   nd->ap.dport, nd->size, nd->com,
			   nd->pid, nd->fd, nd->family, nd->ret_val);
	}
}
#endif
static void test_data_process_func(void *custom_data, struct connect_info_t *event_data)
{
	struct connect_info_t *data = (struct connect_info_t *)event_data;
	int sport;
	char sip[20];
	FILE *file = env_para.file;

	fprintf(file, "=========data evnet handle:%d==========\n", data_count++);
	fprintf(file, "ts:%llu, connect_id_t:: fd:%d, tgid:%u, start:%llu\n", data->rt,
			data->conn_id.fd, data->conn_id.tgid, data->conn_id.start);
	fprintf(file, "proto:%d, role:%d, type:%d\n",
			data->protocol, data->role, data->type);
	if (data->addr.sa.sa_family == AF_INET)
	{
		inet_ntop(AF_INET, &data->addr.in4.sin_addr.s_addr, sip, 16);
		sport = ntohs(data->addr.in4.sin_port);
		fprintf(file, "ipv4::sip:%s, sport:%d\n", sip, sport);
	}
	else if (data->addr.sa.sa_family == AF_INET6)
	{
		// inet_ntop(AF_INET6, &data->addr.in6.sin6_addr.s_addr, sip, 32);
		sport = ntohs(data->addr.in6.sin6_port);
		fprintf(file, "ipv6::sip:%s, sport:%d\n", sip, sport);
	}
	else
	{
		fprintf(file, "wrong family:%d\n", data->addr.sa.sa_family);
	}

	// fprintf(file, "pos:%llu, org_msg:%u, msg_buf:%u, try_pre:%d, len_header:%u\n",
	// 		data->pos, data->org_msg_size, data->msg_buf_size,
	// 		data->try_to_prepend, data->length_header);
	fprintf(file, "msg:%s\n", data->msg);
}

static void test_ctrl_process_func(void *custom_data, struct conn_ctrl_event_t *event_data)
{
	struct conn_ctrl_event_t *data = (struct conn_ctrl_event_t *)event_data;
	char sip[32];
	int sport;
	FILE *file = env_para.file;

	fprintf(file, "==========ctrl event handle:%d=========\n", ctrl_count++);
	fprintf(file, "event type:%d, ts:%llu\n", data->type, data->ts);
	fprintf(file, "connect_id_t:: fd:%d, tgid:%u, start:%llu\n", data->conn_id.fd,
			data->conn_id.tgid, data->conn_id.start);
	if (data->type == EventConnect)
	{
		fprintf(file, "conn_event_t::support_role:%d\n", data->connect.role);
		if (data->connect.addr.sa.sa_family == AF_INET)
		{
			inet_ntop(AF_INET, &data->connect.addr.in4.sin_addr.s_addr, sip, 16);
			sport = ntohs(data->connect.addr.in4.sin_port);
			fprintf(file, "ipv4::sip:%s, sport:%d\n", sip, sport);
		}
		else if (data->connect.addr.sa.sa_family == AF_INET6)
		{
			// inet_ntop(AF_INET6, &data->connect.addr.in6.sin6_addr.s_addr, sip, 32);
			sport = ntohs(data->connect.addr.in6.sin6_port);
			fprintf(file, "ipv6::sip:%s, sport:%d\n", sip, sport);
		}
		else
		{
			fprintf(file, "wrong family:%d\n", data->connect.addr.sa.sa_family);
		}
	}
	if (data->type == EventClose)
	{
		fprintf(file, "close_event_t:: wr_bytes:%lld, rd_bytes:%lld\n", data->close.wr_bytes,
				data->close.rd_bytes);
	}
}

static void test_stat_process_func(void *custom_data, struct conn_stats_event_t *event_data)
{
	struct conn_stats_event_t *data = (struct conn_stats_event_t *)event_data;
	char sip[32];
	int sport;
	FILE *file = env_para.file;

	fprintf(file, "=========stats event handle:%d========\n", stat_count++);
	fprintf(file, "ts:%llu\n", data->ts);
	fprintf(file, "connect_id_t:: fd:%d, tgid:%u, start:%llu\n", data->conn_id.fd,
			data->conn_id.tgid, data->conn_id.start);
	if (data->addr.sa.sa_family == AF_INET)
	{
		inet_ntop(AF_INET, &data->addr.in4.sin_addr.s_addr, sip, 16);
		sport = data->addr.in4.sin_port;
		fprintf(env_para.file, "ipv4::sip:%s, sport:%d\n", sip, sport);
	}
	else if (data->addr.sa.sa_family == AF_INET6)
	{
		// inet_ntop(AF_INET6, &data->addr.in6.sin6_addr.s_addr, sip, 32);
		sport = data->addr.in6.sin6_port;
		fprintf(file, "ipv6::sip:%s, sport:%d\n", sip, sport);
	}
	else
	{
		fprintf(file, "wrong family:%d\n", data->addr.sa.sa_family);
	}

	fprintf(file, "wr_bytes:%lld, rd_bytes:%lld, wr_pkts:%d, rd_pkts:%d\n",
			data->wr_bytes, data->rd_bytes, data->wr_pkts, data->rd_pkts);
	fprintf(file, "last_wr_bytes:%lld, last_rd_bytes:%lld, last_wr_pkts:%d, last_rd_pkts:%d, conn_event:%u\n",
			data->last_output_wr_bytes, data->last_output_rd_bytes,
			data->last_output_wr_pkts, data->last_output_rd_pkts,
			data->conn_events);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static void para_parse(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "P:p:s:d:ofD")) != -1)
	{
		switch (opt)
		{
		case 'P':
			env_para.pid = atoi(optarg);
			break;
		case 'p':
			env_para.proto = atoi(optarg);
			break;
		case 's':
			env_para.self_pid = atoi(optarg);
			break;
		case 'd':
			env_para.data_sample = atoi(optarg);
			break;
		case 'o':
			env_para.port = atoi(optarg);
			break;
		case 'f':
			env_para.file = fopen("netlog", "w+");
			break;
		case 'D':
			env_para.debug = 1;
			break;
		default:
			printf("-P:pid; -p:protocol; -s: self_pid; -d: data_sample; -o: port\n");
			break;
		}
	}
	if (!env_para.file)
	{
		env_para.file = stdout;
	}
}

static void *handle_disable_recover_process(void *arg)
{
	// bool drop = false;
	// int i = 0;
	// while (i++ < 10)
	// {
	// 	sleep(10);

	// 	test_disable_process(drop);
	// 	drop = !drop;
	// }
}

static void *handle_clean(void *arg)
{
	struct connect_id_t conn_id = {0};
	int32_t size = 1;

	conn_id.tgid = 1;
	conn_id.fd = 2;
	printf("handle_clean start, tgid:%u, fd:%d\n", conn_id.tgid, conn_id.fd);
	while (1)
	{
		sleep(10);
		test_update_conn_addr();
		send_self_packet(300);
		ebpf_delete_map_value(&conn_id, size);
	}
}

int send_self_packet(int num)
{
	int clientSocket;
	char buffer[1024];
	struct sockaddr_in serverAddr;
	socklen_t addr_size;
	int i;

	sleep(10);
	/*---- Create the socket. The three arguments are: ----*/
	/* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
	for (i = 0; i < num; i++)
	{
		clientSocket = socket(AF_INET, SOCK_STREAM, 0);

		/*---- Configure settings of the server address struct ----*/
		/* Address family = Internet */
		serverAddr.sin_family = AF_INET;
		/* Set port number, using htons function to use proper byte order */
		serverAddr.sin_port = htons(7891);
		/* Set IP address to localhost */
		serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
		/* Set all bits of the padding field to 0 */
		memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

		/*---- Connect the socket to the server using the address struct ----*/
		addr_size = sizeof serverAddr;
		connect(clientSocket, (struct sockaddr *)&serverAddr, addr_size);

		/*---- Read the message from the server into the buffer ----*/
		//   recv(clientSocket, buffer, 1024, 0);
		recvfrom(clientSocket, buffer, 1024, 0, NULL, 0);
		// ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
		//                  struct sockaddr *src_addr, socklen_t *addrlen);
		/*---- Print the received message ----*/
		printf("num:%d, Data received: %s", i, buffer);
		close(clientSocket);
	}

	return 0;
}
/*
test result:
==========ctrl event handle:40=========
event type:0, ts:1444860390337476
connect_id_t:: fd:1234, tgid:1234, start:1234
conn_event_t::support_role:1
ipv4::sip:127.0.0.1, sport:1234
*/
static void test_update_conn_addr(void)
{
	struct connect_id_t conn_id = {
		.tgid = 1234,
		.fd = 1234,
		.start = 1234,
	};
	union sockaddr_t dst_addr;
	dst_addr.sa.sa_family = AF_INET;
	dst_addr.in4.sin_addr.s_addr = inet_addr("127.0.0.1");
	dst_addr.in4.sin_port = htons(1234);
	uint16_t local_port = 12345;

	ebpf_update_conn_addr(&conn_id, &dst_addr, local_port, false);
}

static void test_disable_process(bool drop)
{
	uint32_t pid = 73068;
	ebpf_disable_process(pid, drop);
	printf("%d disable process %d\n", pid, drop);
}

int main(int argc, char **argv)
{
	int err;
	int stop_flag = 0;
	// void *handle;
	pthread_t tid;
	char so_file[64] = "/root/gitee-github/coolbpf/build/tools/examples/net/net";
	// char btf_file[128] = "/boot/vmlinux-4.19.91-007.ali4000.alios7.x86_64";
	Dl_info dlinfo;

	para_parse(argc, argv);

	env_para.self_pid = getpid();
	signal(SIGINT, sig_handler);
	ebpf_setup_print_func(test_print_func);
	ebpf_setup_net_event_process_func(test_ctrl_process_func, NULL);
	ebpf_setup_net_info_process_func(test_data_process_func, NULL);
	ebpf_setup_net_statistics_process_func(test_stat_process_func, NULL);
	err = dladdr(ebpf_cleanup_dog, &dlinfo);
	if (err)
	{
		printf("laddr failed, err:%s\n", strerror(err));
	}
	long uprobe_offset = (long)dlinfo.dli_saddr - (long)dlinfo.dli_fbase;
	err = dladdr(ebpf_update_conn_addr, &dlinfo);
	if (err)
	{
		printf("laddr failed, err:%s\n", strerror(err));
	}
	long upca_offset = (long)dlinfo.dli_saddr - (long)dlinfo.dli_fbase;
	err = dladdr(ebpf_disable_process, &dlinfo);
	if (err)
	{
		printf("laddr failed, err:%s\n", strerror(err));
	}
	long disproc_offset = (long)dlinfo.dli_saddr - (long)dlinfo.dli_fbase;

	printf("uprobe_offset:%x, upcap_offset:%x, disproc_offset:%x\n", uprobe_offset, upca_offset, disproc_offset, disproc_offset);
	err = pthread_create(&tid, NULL, &handle_disable_recover_process, NULL);
	if (err)
	{
		printf("pthread create failed:%s\n", strerror(err));
		return err;
	}
	err = ebpf_init(NULL, 0, so_file, strlen(so_file), uprobe_offset, upca_offset, disproc_offset, 0);
	if (err)
	{
		printf("init failed, err:%d\n", err);
		return err;
	}
	printf("input para pid:%d, proto:%d, self:%d, sample:%d, port:%d, debug:%d\n",
		   env_para.pid, env_para.proto, env_para.self_pid, env_para.data_sample, env_para.port, env_para.debug);

	printf("net init end...\n");

	set_ebpf_int_config((int32_t)PROTOCOL_FILTER, env_para.proto);
	set_ebpf_int_config((int32_t)TGID_FILTER, 1240144);
	set_ebpf_int_config((int32_t)PORT_FILTER, -1);
	set_ebpf_int_config((int32_t)SELF_FILTER, -1);
	set_ebpf_int_config((int32_t)DATA_SAMPLING, env_para.data_sample);
	map_fd = ebpf_get_fd();

	printf("net config end...\n");
	err = ebpf_start();
	if (err)
	{
		printf("start failed, err:%d\n", err);
		ebpf_stop();
		return 0;
	}
	printf("net start end...\n");
	while (1)
	{
		err = ebpf_poll_events(100, &stop_flag);
		if (exiting)
		{
			if (env_para.file != stdout)
			{
				fclose(env_para.file);
			}
			break;
		}
	}

	return 0;
}
