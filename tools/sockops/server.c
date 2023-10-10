#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#define IPADDRESS "127.0.0.1"
#define PORT 8001
#define MAXSIZE 87380
#define LISTENQ 5
#define FDSIZE 10000
#define EPOLLEVENTS 10000

static int socket_bind(const char *ip, int port);
static void do_epoll(int listenfd);
static void handle_events(int epollfd, struct epoll_event *events, int num, int listenfd, char *buf);
static void handle_accpet(int epollfd, int listenfd);
static void do_read(int epollfd, int fd, char *buf);
static void do_write(int epollfd, int fd, char *buf);
static void add_event(int epollfd, int fd, int state);
static void modify_event(int epollfd, int fd, int state);
static void delete_event(int epollfd, int fd, int state);

static int online_counter = 0;
static int read_counter = 0;
static int accept_counter = 0;
static int every = 0;
static int delay = 0;

int main(int argc, char *argv[])
{
	int listenfd;
	if (argc < 3) {
		printf("usage: server every delay\n");
		exit(-1);
	}

	every = atoi(argv[1]);
	delay = atoi(argv[2]);
	if (every < 2) {
		every = 2;
	}
	if (delay < 2) {
		delay = 2;
	}

	listenfd = socket_bind(IPADDRESS, PORT);
	listen(listenfd, LISTENQ);
	do_epoll(listenfd);
	return 0;
}

static int socket_bind(const char *ip, int port)
{
	int listenfd;
	struct sockaddr_in servaddr;
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) {
		perror("socket error:");
		exit(1);
	}
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	inet_pton(AF_INET, ip, &servaddr.sin_addr);
	servaddr.sin_port = htons(port);
	if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
		perror("bind error: ");
		exit(1);
	}
	return listenfd;
}

static void do_epoll(int listenfd)
{
	int epollfd;
	struct epoll_event events[EPOLLEVENTS];
	int ready_cnt;
	char buf[MAXSIZE];
	memset(buf, 0, MAXSIZE);
	epollfd = epoll_create(FDSIZE);
	add_event(epollfd, listenfd, EPOLLIN);
	for (;;) {
		ready_cnt = epoll_wait(epollfd, events, EPOLLEVENTS, -1);
		handle_events(epollfd, events, ready_cnt, listenfd, buf);
	}
	close(epollfd);
}

static void handle_events(int epollfd, struct epoll_event *events, int num, int listenfd, char *buf)
{
	int i;
	int fd;

	for (i = 0; i < num; i++) {
		fd = events[i].data.fd;
		// If fd is a listen fd, we do accept(), otherwise it is a
		// connected fd, we should read buf if EPOLLIN occured.
		if ((fd == listenfd) && (events[i].events & EPOLLIN))
			handle_accpet(epollfd, listenfd);
		else if (events[i].events & EPOLLIN)
			do_read(epollfd, fd, buf);
		else if (events[i].events & EPOLLOUT)
			do_write(epollfd, fd, buf);
	}
}

static void handle_accpet(int epollfd, int listenfd)
{
	int clifd;
	struct sockaddr_in cliaddr;
	socklen_t cliaddrlen;

	clifd = accept(listenfd, (struct sockaddr *)&cliaddr, &cliaddrlen);
	if (clifd == -1)
		perror("Accpet error:");
	else {
		online_counter++;
		accept_counter++;
		//printf("Accept a new client: %s:%d,online:%d\n", inet_ntoa(cliaddr.sin_addr), cliaddr.sin_port,online_counter);
		add_event(epollfd, clifd, EPOLLIN);
	}
	if (accept_counter > 1 && accept_counter % 100 == 0) {
		printf("every %-5d delay %2d s;  acc:%-10d read:%-10d online:%-10d\n", every, delay, accept_counter, read_counter, online_counter);
	}
}

static void do_read(int epollfd, int fd, char *buf)
{
	int nread;

	nread = read(fd, buf, MAXSIZE);
	if (nread == -1) {
		//perror("Read error:");
		delete_event(epollfd, fd, EPOLLIN);
		online_counter--;
		close(fd);
	} else if (nread == 0) {
		//printf("client closed,online:%d\n",online_counter);
		delete_event(epollfd, fd, EPOLLIN);
		online_counter--;
		close(fd);
	} else {
		//printf("Read message : %d,online:%d\n", nread,online_counter);
		modify_event(epollfd, fd, EPOLLOUT);
		read_counter++;
	}
}

static void do_write(int epollfd, int fd, char *buf)
{
	int nwrite;

	struct timespec ts;	// 定义一个timespec结构体，用于存储时间信息
	clock_gettime(CLOCK_MONOTONIC, &ts);	// 调用clock_gettime函数，获取当前时间，存储在ts中

	// 返回ts中的秒数乘以10的9次方，加上纳秒数
	// 使用当前时间的纳秒数作为随机数种子
	srand(ts.tv_sec * 1000000000LL + ts.tv_nsec);
	//srand(time(0));  //连续两个请求产生相同的随机数，同时delay
	if (rand() % every == (every - 1)) {

		struct sockaddr_in loc_addr;
		int len = sizeof(sizeof(loc_addr));
		int local_port = 0;
		memset(&loc_addr, 0, len);
		if (-1 == getsockname(fd, (struct sockaddr *)&loc_addr, &len)) {
			perror("getsockname");
		}
		printf("sleep %d on %d\n", delay, ntohs(loc_addr.sin_port));

		sleep(delay);
	}

	nwrite = write(fd, buf, strlen(buf) + 1);
	if (nwrite == -1) {
		perror("Write error:");
		delete_event(epollfd, fd, EPOLLOUT);
		online_counter--;
		close(fd);
	} else
		modify_event(epollfd, fd, EPOLLIN);

	memset(buf, 0, MAXSIZE);
}

static void add_event(int epollfd, int fd, int state)
{
	struct epoll_event ev;
	ev.events = state;
	ev.data.fd = fd;
	if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
		printf("Add event failed!\n");
	}
}

static void delete_event(int epollfd, int fd, int state)
{
	struct epoll_event ev;
	ev.events = state;
	ev.data.fd = fd;
	if (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &ev) < 0) {
		printf("Delete event failed!\n");
	}
}

static void modify_event(int epollfd, int fd, int state)
{
	struct epoll_event ev;
	ev.events = state;
	ev.data.fd = fd;
	if (epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &ev) < 0) {
		printf("Modify event failed!\n");
	}
}
