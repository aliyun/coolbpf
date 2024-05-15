/*
 * Author: Chen Tao 
 * Create: Sun Feb 20 20:32:45 2022
 */

#ifndef COOLBPF_NET_H
#define COOLBPF_NET_H

#ifndef __VMLINUX_H__
#include <argp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>
#endif

#define CONN_DATA_MAX_SIZE 16384
#define DATA_SAMPLE_ALL 100

enum support_proto_e
{
  ProtoUnknown = 0,
  ProtoHTTP = 1,
  ProtoMySQL = 2,
  ProtoDNS = 3,
  ProtoRedis = 4,
  ProtoKafka = 5,
  ProtoPGSQL = 6,
  ProtoMongo = 7,
  ProtoDubbo = 8,
  ProtoHSF = 9,
  NumProto,
};
enum support_role_e
{
  IsUnknown = 0x01,
  IsClient = 0x02,
  IsServer = 0x04,
};

enum tgid_config_e
{
  TgidIndex = 0,
  TgidNum,
};

enum support_conn_status_e
{
  StatusOpen,
  StatusClose,
};

enum support_syscall_e
{
  FuncUnknown,
  FuncWrite,
  FuncRead,
  FuncSend,
  FuncRecv,
  FuncSendTo,
  FuncRecvFrom,
  FuncSendMsg,
  FuncRecvMsg,
  FuncMmap,
  FuncSockAlloc,
  FuncAccept,
  FuncAccept4,
  FuncSecuritySendMsg,
  FuncSecurityRecvMsg,
  FuncSendMmsg,
  FuncRecvMmsg,
  FuncWriteV,
  FuncReadV,
};

enum support_direction_e
{
  DirUnknown,
  DirIngress,
  DirEgress,
};

enum support_event_e
{
  EventConnect,
  EventClose,
};

enum support_tgid_e
{
  TgidUndefine,
  TgidAll,
  TgidMatch,
  TgidUnmatch,
};

enum support_type_e
{
  TypeUnknown,
  TypeRequest,
  TypeResponse
};

struct addr_pair_t
{
  uint32_t saddr;
  uint32_t daddr;
  uint16_t sport;
  uint16_t dport;
};

struct map_syscall_t
{
  int funcid;
  char *funcname;
};

struct mproto_t
{
  int protocol;
  char *proto_name;
};

struct test_data
{
  struct addr_pair_t ap;
  uint64_t size;
  int fd;
  char com[16];
  char func[16];
  int pid;
  int family;
  int funcid;
  int ret_val;
};

union sockaddr_t
{
  struct sockaddr sa;
  struct sockaddr_in in4;
  struct sockaddr_in6 in6;
};

struct connect_id_t
{
  int32_t fd;
  uint32_t tgid;
  uint64_t start;
};

struct conn_event_t
{
  union sockaddr_t addr;
  enum support_role_e role;
};

struct close_event_t
{
  int64_t wr_bytes;
  int64_t rd_bytes;
};

struct conn_ctrl_event_t
{
  enum support_event_e type;
  uint64_t ts;
  struct connect_id_t conn_id;
  union
  {
    struct conn_event_t connect;
    struct close_event_t close;
  };
};

struct conn_data_event_t
{
  struct attr_t
  {
    uint64_t ts;
    struct connect_id_t conn_id;
    union sockaddr_t addr;
    enum support_proto_e protocol;
    enum support_role_e role;
    enum support_type_e type;
    enum support_direction_e direction;
    enum support_syscall_e syscall_func;
    uint64_t pos;
    uint32_t org_msg_size;
    uint32_t msg_buf_size;
    bool try_to_prepend;
    uint32_t length_header;
  } attr;
  char msg[CONN_DATA_MAX_SIZE];
};

struct conn_stats_event_t
{
  uint64_t ts;
  struct connect_id_t conn_id;
  union sockaddr_t addr;
  enum support_role_e role;
  int64_t wr_bytes;
  int64_t rd_bytes;
  int32_t wr_pkts;
  int32_t rd_pkts;
  int64_t last_output_wr_bytes;
  int64_t last_output_rd_bytes;
  int32_t last_output_wr_pkts;
  int32_t last_output_rd_pkts;
  uint32_t conn_events;
};

struct connect_info_t
{
  struct connect_id_t conn_id;
  union sockaddr_t addr;
  enum support_proto_e protocol;
  enum support_role_e role;
  enum support_type_e type;
  int64_t wr_bytes;
  int64_t rd_bytes;
  int32_t wr_pkts;
  int32_t rd_pkts;
  int64_t last_output_wr_bytes;
  int64_t last_output_rd_bytes;
  int32_t last_output_wr_pkts;
  int32_t last_output_rd_pkts;
  int32_t total_bytes_for_proto;
  uint64_t last_output_time;
  size_t prev_count;
  char prev_buf[4];
  bool try_to_prepend;
  bool is_sample;
};

struct protocol_type_t
{
  enum support_proto_e protocol;
  enum support_type_e type;
};

struct tg_info_t
{
  uint32_t tgid;
  int32_t fd;
  enum support_role_e role;
};

struct conn_param_t
{
  const struct sockaddr *addr;
  int32_t fd;
};

struct accept_param_t
{
  struct sockaddr *addr;
  struct socket *accept_socket;
};

struct close_param_t
{
  int32_t fd;
};

struct data_param_t
{
  enum support_syscall_e syscall_func;
  bool real_conn;
  int32_t fd;
  const char *buf;
  const struct iovec *iov;
  size_t iovlen;
  unsigned int *msg_len;
};

struct config_info_t
{
  int32_t port;
  int32_t self_pid;
  int32_t data_sample;
};

#ifndef __VMLINUX_H__

enum callback_type_e
{
  CTRL_HAND = 0,
  DATA_HAND,
  STAT_HAND,
#ifdef NET_TEST
  TEST_HAND,
#endif
  MAX_HAND,
};

#define MAX_PROTOCOL_NUM 5
#ifdef NET_TEST
typedef void (*net_test_process_func_t)(void *custom_data, struct test_data *event);
#endif
typedef void (*net_data_process_func_t)(void *custom_data, struct conn_data_event_t *event);
typedef void (*net_ctrl_process_func_t)(void *custom_data, struct conn_ctrl_event_t *event);
typedef void (*net_statistics_process_func_t)(void *custom_data, struct conn_stats_event_t *event);
typedef void (*net_lost_func_t)(void *custom_data, enum callback_type_e type, uint64_t lost_count);
typedef int (*net_print_fn_t)(int16_t level, const char *format, va_list args);

#ifdef NET_TEST
void ebpf_setup_net_test_process_func(net_test_process_func_t func, void *custom_data);
#endif
void ebpf_setup_net_data_process_func(net_data_process_func_t func, void *custom_data);
void ebpf_setup_net_event_process_func(net_ctrl_process_func_t func, void *custom_data);
void ebpf_setup_net_statistics_process_func(net_statistics_process_func_t func, void *custom_data);
void ebpf_setup_net_lost_func(net_lost_func_t func, void *custom_data);
void ebpf_setup_print_func(net_print_fn_t func);

enum ebpf_config_primary_e
{
  PROTOCOL_FILTER = 0, // 默认值-1。协议类型过滤器，为-1时代表Trace所有协议，其他只允许某一协议
  TGID_FILTER,         // 默认值-1。进程过滤器，为-1时代表Trace所有进程，其他只允许某一进程
  SELF_FILTER,         // 默认值-1。是否Disable自身的Trace，为-1代表不Disable，其他情况会传入本进程的ID，这时需要过滤掉该进程所有的数据
  PORT_FILTER,         // 默认值-1。端口过滤器，为-1时代表Trace所有端口，其他只允许某一端口
  DATA_SAMPLING,       // 默认值100。采样策略，取值0 -> 100，代表采样的百分比(0全部丢弃，100全部上传)
                       // 采样的策略：tcp的包，连接建立的ns时间 % 100， 小于采样率即为需要上传，大于的话对该连接进行标记，不上传Data、Ctrl（统计数据还是要上传）
                       //           udp的包，接收到数据包的ns时间 % 100， 小于采样率即为需要上传，大于的话不上传Data（统计数据还是要上传 @note 要注意统计数据Map的清理策略）
  PERF_BUFFER_PAGE,    // ring buffer page count, 默认128个页，也就是512KB, opt2 的类型是 callback_type_e
};
// opt1 列表：
//      AddProtocolFilter、RemoveProtocolFilter
//      AddTGIDFilter、RemoveTGIDFilter
//      AddConnFilter、RemoveConnFilter
//      AddPortFilter、RemovePortFilter

/**
 * @brief 配置各类参数，例如监听的TGID、协议、端口等黑白名单，采集策略等
 *        每个参数由对应的配置类型来推导，例如 opt1是 AddPortFilter opt2 是 BlackList，params_count 是1，params = {&uint16_t(80)}, params_len = {2}
 * @param opt1 配置主类型：ebpf_config_primary_e
 * @param opt2 配置副类型，[暂未使用]
 * @param params_count 参数个数 [目前均为1]
 * @param params 参数列表 [int32]
 * @param params_len 每个参数的长度，[均为4]
 *
 * int32_t disabledPort = 443;
 * int32_t * params[] = {&disabledPort};
 * int32_t paramsLen[] = {4};
 * ebpf_config(PORT_FILTER, 0, 1, params, paramsLen);
 *
 * if ((ebpf_config_primary_e)opt1 == PORT_FILTER) {
 *      disabledPort = (int32_t *)(params[0])[0];
 *      // update to bpf code
 * }
 */
void ebpf_config(int32_t opt1, int32_t opt2, int32_t params_count, void **params, int32_t *params_len);

/**
 * @brief 由外层调用，每次调用poll数据，然后交给预先setup好的3个回调来处理，每次poll数据，需要检查stop_flag是否 >0，如果 > 0立即退出。
 * 顺序：控制、统计、Data
 *
 * @param max_events 最多处理的事件数
 * @param stop_flag 是否需要立即退出
 * @return int32_t 正数，返回处理的事件数； -100，stop_flag触发；其他，错误码
 */
int32_t ebpf_poll_events(int32_t max_events, int32_t *stop_flag);

// 启动时，会调用init，然后调用start
/*
 * @btf btf路径包括btf文件全名, 传NULL就默认在/usr/lib/vmlinux-**
 * @so so文件路径包括so文件全名，uprobe解析用到
 * @return int32_t 0:success, others:failed
 * @uprobe_offset cleanup_dog函数偏移
 * @update_conn_addr_offset update_conn_addr函数偏移
 * @upps_offset disable_process函数偏移
 * @upcr_offset ebpf_update_conn_role 函数偏移
 */
int32_t ebpf_init(char *btf, int32_t btf_size, char *so, int32_t so_size, long uprobe_offset,
                  long upca_offset, long upps_offset, long upcr_offset);
/*
 * @return int32_t 0:success, others:failed
 */
int32_t ebpf_start(void);

// 是否支持运行期间动态的 start stop？ 如果不支持，那只有程序退出的时候会调用/或者永远不调用，等进程销毁自动回收
/*
 * @return int32_t 0:success, others:failed
 */
int32_t ebpf_stop(void);

/*
 * @return 返回fd
 */
int32_t ebpf_get_fd(void);

// 这里的key是u64类型,conn_info_map的key
int32_t ebpf_get_next_key(int32_t fd, const void *key, void *next_key);

// 这里的key传connet_id_t结构体
void ebpf_delete_map_value(void *key, int32_t size);

// 用于uprobe, 没有实现内容
void ebpf_cleanup_dog(void *key, int32_t size);

// 更新conn对应的Remote address和local port, uprobe
void ebpf_update_conn_addr(struct connect_id_t *conn_id, union sockaddr_t *dest_addr, uint16_t local_port, bool drop);

// 更新process 观察范围，动态增加pid，drop 为true 是进行删除操作。
void ebpf_disable_process(uint32_t pid, bool drop);

// 更新conn对应的角色，某些协议内核态无法判断角色
void ebpf_update_conn_role(struct connect_id_t *conn_id, enum support_role_e role_type);

#endif
#endif
