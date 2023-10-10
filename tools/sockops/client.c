// 2 thread epoll client
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

#define MAX_BUFFER      1024*1024*16
#define MAX_EPOLLSIZE   (384*1024)
#define MAX_PORT        100
//#define max_conn        405000
//#define max_conn        3

#define TIME_SUB_MS(tv1, tv2)  ((tv1.tv_sec - tv2.tv_sec) * 1000 + (tv1.tv_usec - tv2.tv_usec) / 1000)
#define TIME_MS(tv1)  ((tv1.tv_sec) * 1000 + (tv1.tv_usec) / 1000)

#define dbg_log(f, a...) \
	if(verbose>0) fprintf(stdout, f, ##a);

struct epoll_event events[MAX_EPOLLSIZE];
static pthread_t threads[16];
static int epoll_fd = 0;

static int verbose = 1;
static int s = 1;		// sleep time
static int max_conn = 10;
static int max_send = 10;
static int msg_size = 1;
static int batch = 1;
static int online_counter = 0;

static unsigned int retran_counter = 0;	// form batch
static int conn_counter = 0;	// connect() counter
static int fd_to_port[65535] = { 0 };	// fd as index

static int trans_counter = 0;	// send() counter
static char trans_status[1000] = { 0 };	// every 1000 recv time info
static int trans_time[65535] = { 0 };	// read->write                        by FD

static int finish_counter = 0;	// connect() and recv() finish counter
static char finish_status[1000] = { 0 };	// every 1000 close time info
static int conn_time[65535] = { 0 };	// connect->close                     by local FD

static int receive[65535] = { 0 };	// recv() sum                         by local PORT
static int fd_use_counter[65535] = { 0 };

static void signal_handler(int sig)
{
	int i = 0;
	printf("Result:\n");
	printf("fd usage:\n");
	for (i = 0; i < 65535; i++) {
		if (fd_use_counter[i] > 0) {
			printf("fd:%d counter:%d\n", i, fd_use_counter[i]);
		}
	}
	printf("online:%d,conn_counter:%d,finish_counter:%d,trans_counter:%d,retran_counter:%d\n", online_counter, conn_counter, finish_counter, trans_counter, retran_counter);
	exit(0);
}

static int set_nonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return flags;
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0)
		return -1;
	return 0;
}

static int set_reuseaddr(int fd)
{
	int reuse = 1;
	return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse));
}

static void del_fd(int epoll_fd, int cfd)
{
	//printf("disconnect cfd:%d\n", cfd);
	struct epoll_event ev;
	ev.data.fd = cfd;
	ev.events = EPOLLIN | EPOLLOUT;
	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, cfd, &ev);
	close(cfd);
	online_counter--;
}

char delay_to_char(int delay)
{
	if (delay <= 0) {
		return '.';
	} else if (delay < 10) {
		return '-';
	} else if (delay < 100) {
		return '^';
	} else {
		return '*';
	}
}

void update_trans_status(int fd)
{
	struct timeval tm;
	int i = 0;

	gettimeofday(&tm, NULL);
	int delay = TIME_MS(tm) - trans_time[fd];

	trans_status[trans_counter % 1000] = delay_to_char(delay);

	if (delay > 100) {
		printf("RW port:%d,delay:%d ms\n", fd_to_port[fd], delay);
	}

	if (trans_counter > 0 && (trans_counter % 999 == 0)) {
		printf("RW:");
		for (i = 0; i < 1000; i++) {
			if (trans_status[i] != "\0") {
				printf("%c", trans_status[i]);
			}
		}
		printf("\n");
		memset(trans_status, 0, 1000);
	}
	trans_counter++;
}

void update_conn_finish_status(int fd)
{
	struct timeval tm;
	int i = 0;

	gettimeofday(&tm, NULL);

	int delay = TIME_MS(tm) - conn_time[fd];
	finish_status[finish_counter % 1000] = delay_to_char(delay);

	printf("from port:%d,delay:%d ms\n", fd_to_port[fd], delay);

	if (finish_counter > 0 && (finish_counter % 999 == 0)) {
		printf("CC:");
		for (i = 0; i < 1000; i++) {
			if (finish_status[i] != "\0") {
				printf("%c", finish_status[i]);
			}
		}
		printf("\n");
		memset(finish_status, 0, 1000);
	}
	finish_counter++;
}

void do_work()
{
	int i = 0;
	int nfds = 0;
	int fd = 0;

	struct epoll_event ev;
	struct timeval tm;
	char *r_buf = malloc(MAX_BUFFER);

	while (1) {
		nfds = epoll_wait(epoll_fd, events, MAX_EPOLLSIZE, 100);
		for (i = 0; i < nfds; i++) {
			fd = events[i].data.fd;

			if (events[i].events & EPOLLIN) {
				memset(r_buf, 0, MAX_BUFFER);
				ssize_t length = recv(fd, r_buf, MAX_BUFFER, 0);
				if (length > 0) {
					receive[fd_to_port[fd]] = receive[fd_to_port[fd]] + length;

					if ((receive[fd_to_port[fd]] >= (msg_size * batch)) || trans_counter == max_send) {
						dbg_log("RECV %d, total %d, and >= %d\n", length, receive[fd_to_port[fd]], msg_size);
						update_conn_finish_status(fd);
						del_fd(epoll_fd, fd);
					} else {
						dbg_log("RECV %d, total %d, but < %d * %d(batch)\n", length, receive[fd_to_port[fd]], msg_size, batch);
						retran_counter++;
						ev.data.fd = fd;
						ev.events = EPOLLOUT;
						if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) < 0) {
							printf("Modify event failed!\n");
						}
					}
				} else if (length == 0) {
					del_fd(epoll_fd, fd);
				} else {
					if (errno == EINTR || errno == EAGAIN)
						continue;
					printf(" Error fd:%d, errno:%d\n", fd, errno);
				}
			} else if (events[i].events & EPOLLOUT) {
				if (trans_counter < max_send) {
					char *s_buf = malloc(msg_size);
					gettimeofday(&tm, NULL);
					trans_time[fd] = TIME_MS(tm);

					memset(s_buf, 'A', msg_size);
					s_buf[msg_size - 1] = '\0';

					int s_size = send(fd, s_buf, msg_size, 0);
					dbg_log("SEND %d of %d\n", s_size, msg_size);
					free(s_buf);

					update_trans_status(fd);

					ev.data.fd = fd;
					ev.events = EPOLLIN;
					if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev) < 0) {
						printf("Modify event failed!\n");
					}
				} else {
					del_fd(epoll_fd, fd);
				}

			}
			usleep(s * 1000 * 1000);
		}
	}

}

int main(int argc, char **argv)
{
	struct sockaddr_in addr;
	const char *ip = "127.0.0.1";
	int port = 8001;
	struct timeval tm;

	if (argc < 6) {
		printf("usage: client max_conn msg_size batch sleep_time max_send verbose\n");
		exit(-1);
	}

	max_conn = atoi(argv[1]);
	if (max_conn < 0) {
		max_conn = 10;
	}

	msg_size = atoi(argv[2]);
	if (msg_size < 1) {
		msg_size = 1;
	}

	batch = atoi(argv[3]);
	if (batch < 1) {
		batch = 1;
	}
	s = atoi(argv[4]);
	if (s < 0) {
		s = 1;
	}
	max_send = atoi(argv[5]);
	if (verbose < 0) {
		verbose = 10;
	}
	verbose = atoi(argv[6]);
	if (verbose < 0) {
		verbose = 1;
	}

	epoll_fd = epoll_create(MAX_EPOLLSIZE);

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip);
	addr.sin_port = htons(port);

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGABRT, signal_handler);

	pthread_create(&threads[1], NULL, do_work, NULL);

	while (1) {
		struct epoll_event ev;
		int fd = 0;

		if (online_counter < max_conn && trans_counter < max_send) {
			fd = socket(AF_INET, SOCK_STREAM, 0);
			if (fd == -1) {
				perror("socket");
				goto err;
			}
			if (connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
				perror("connect");
				goto err;
			}
			//dbg_log("new connection at %d\n",fd);

			struct sockaddr_in loc_addr;
			int len = sizeof(sizeof(loc_addr));
			int local_port = 0;
			memset(&loc_addr, 0, len);
			if (-1 == getsockname(fd, (struct sockaddr *)&loc_addr, &len)) {
				perror("getsockname");
				goto err;
			}
			if (loc_addr.sin_family == AF_INET) {	// 打印信息 
				local_port = ntohs(loc_addr.sin_port);
				dbg_log("local port: %u\n", local_port);

				fd_to_port[fd] = local_port;

				conn_counter++;
				online_counter++;	// add and minus
				receive[fd_to_port[fd]] = 0;
				fd_use_counter[fd]++;

				set_nonblock(fd);
				set_reuseaddr(fd);

				gettimeofday(&tm, NULL);
				conn_time[fd] = TIME_MS(tm);

				ev.data.fd = fd;
				ev.events = EPOLLOUT;
				epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);

			} else {
				perror("getsockname");
				goto err;
			}

		}
	}
	close(epoll_fd);
	printf("success end\n");
	return 0;
      err:
	printf("error : %s\n", strerror(errno));
	return 0;
}
