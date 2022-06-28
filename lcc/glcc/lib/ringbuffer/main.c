#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>


typedef void (*register_module_helper_t)(struct bpf_func_proto *helper);
typedef void (*register_module_map_t)(struct bpf_map_ops *map);
typedef void (*unregister_module_helper_t)(struct bpf_func_proto *helper);
typedef void (*unregister_module_map_t)(struct bpf_map_ops *map);

register_module_helper_t register_module_helper_p = NULL;
unregister_module_helper_t unregister_module_helper_p = NULL;
register_module_map_t register_module_map_p = NULL;
unregister_module_map_t unregister_module_map_p = NULL;

extern struct bpf_map_ops ringbuf_map_ops;
extern struct bpf_func_proto bpf_ringbuf_reserve_proto;
extern struct bpf_func_proto bpf_ringbuf_submit_proto;
extern struct bpf_func_proto bpf_ringbuf_discard_proto;
extern struct bpf_func_proto bpf_ringbuf_output_proto;
extern struct bpf_func_proto bpf_ringbuf_query_proto;

static int ringbuffer_init(void)
{
    register_module_helper_p = (register_module_helper_t)kallsyms_lookup_name("register_module_helper");
    if (register_module_helper_p == NULL)
        goto fail_find;

    unregister_module_helper_p = (register_module_helper_t)kallsyms_lookup_name("unregister_module_helper");
    if (unregister_module_helper_p == NULL)
        goto fail_find;

    register_module_map_p = (register_module_map_t)kallsyms_lookup_name("register_module_map");
    if (register_module_map_p == NULL)
        goto fail_find;

    unregister_module_map_p = (register_module_map_t)kallsyms_lookup_name("unregister_module_map");
    if (unregister_module_map_p == NULL)
        goto fail_find;


    register_module_map_p(&ringbuf_map_ops);
    register_module_helper_p(&bpf_ringbuf_reserve_proto);
    register_module_helper_p(&bpf_ringbuf_submit_proto);
    register_module_helper_p(&bpf_ringbuf_discard_proto);
    register_module_helper_p(&bpf_ringbuf_output_proto);
    register_module_helper_p(&bpf_ringbuf_query_proto);
	return 0;
fail_find:
    printk(KERN_NOTICE "failed to find kernel symbols\n");
	return -1;
}
void ringbuffer_exit(void)
{
    if (unregister_module_map_p)
        unregister_module_map_p(&ringbuf_map_ops);
    if (unregister_module_helper_p)
    {
        unregister_module_helper_p(&bpf_ringbuf_reserve_proto);
        unregister_module_helper_p(&bpf_ringbuf_submit_proto);
        unregister_module_helper_p(&bpf_ringbuf_discard_proto);
        unregister_module_helper_p(&bpf_ringbuf_output_proto);
        unregister_module_helper_p(&bpf_ringbuf_query_proto);
    }
}

module_init(ringbuffer_init);
module_exit(ringbuffer_exit);
