
#ifndef __BPF_CORE_HELPER_H
#define __BPF_CORE_HELPER_H

#ifdef __VMLINUX_H__

union ktime___310
{
    s64 tv64;
};
typedef union ktime___310 ktime_t___310;
struct sk_buff___310
{
    ktime_t___310 tstamp;
};

static __always_inline u64 bpf_core_skb_tstamp(struct sk_buff *skb)
{
    u64 ts;
    ktime_t___310 ktime310;
    if (bpf_core_field_exists(ktime310.tv64))
    {
        struct sk_buff___310 *skb310 = skb;
        bpf_core_read(&ktime310, sizeof(ktime310), &skb310->tstamp);
        ts = ktime310.tv64;
    }
    else
    {
        bpf_probe_read(&ts, sizeof(u64), &skb->tstamp);
    }
    return ts;
}

struct msghdr___310
{
    struct iovec *msg_iov;
};

// libbpf: prog 'kprobe__raw_sendmsg': relo #3: kind <byte_off> (0), spec is [346] struct msghdr.msg_iter.iov (0:2:4:0 @ offset 40)
static __always_inline void *bpf_core_msghdr_base(struct msghdr *msg)
{
    void *ptr;
    if (bpf_core_field_exists(msg->msg_iter))
    {
        BPF_CORE_READ_INTO(&ptr, msg, msg_iter.iov, iov_base);
    }
    else
    {
        struct msghdr___310 *msg310 = msg;;
        BPF_CORE_READ_INTO(&ptr, msg310, msg_iov, iov_base);
    }
    return ptr;
}

#endif

#endif

