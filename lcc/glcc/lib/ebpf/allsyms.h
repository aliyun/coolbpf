#ifndef ALL_SYMS__
#define ALL_SYMS__

#include <linux/perf_event.h>
#include <linux/kallsyms.h>


typedef void (*trace_printk_init_buffers_t)(void);
typedef void (*perf_prepare_sample_t)(struct perf_event_header *header,
			 struct perf_sample_data *data,
			 struct perf_event *event,
			 struct pt_regs *regs);
typedef int (*perf_output_begin_t)(struct perf_output_handle *handle,
		      struct perf_event *event, unsigned int size);
typedef void (*perf_output_sample_t)(struct perf_output_handle *handle,
			struct perf_event_header *header,
			struct perf_sample_data *data,
			struct perf_event *event);
typedef void (*perf_output_end_t)(struct perf_output_handle *handle);
typedef void (*free_uid_t)(struct user_struct *);
typedef void *(*__vmalloc_node_range_t)(unsigned long size, unsigned long align,
			unsigned long start, unsigned long end, gfp_t gfp_mask,
			pgprot_t prot, int node, const void *caller);
typedef int (*get_callchain_buffers_t)(void);
typedef void (*sha_init_t)(__u32 *buf);
typedef void (*sha_transform_t)(__u32 *digest, const char *data, __u32 *W);
typedef void *(*module_alloc_t)(unsigned long size);
typedef void (*module_free_t)(struct module *mod, void *module_region);
typedef struct trace_event *(*ftrace_find_event_t)(int type);
typedef void (*perf_callchain_kernel_t)(struct perf_callchain_entry *entry, struct pt_regs *regs);

extern trace_printk_init_buffers_t trace_printk_init_buffers_p;
extern perf_prepare_sample_t perf_prepare_sample_p;
extern perf_output_begin_t perf_output_begin_p;
extern perf_output_sample_t perf_output_sample_p;
extern perf_output_end_t perf_output_end_p;
extern free_uid_t free_uid_p;
extern __vmalloc_node_range_t __vmalloc_node_range_p;
extern get_callchain_buffers_t get_callchain_buffers_p;
extern sha_init_t sha_init_p;
extern sha_transform_t sha_transform_p;
extern module_alloc_t module_alloc_p;
extern module_free_t module_free_p;
// extern struct file_operations *perf_fops_p;
extern ftrace_find_event_t ftrace_find_event_p;
extern perf_callchain_kernel_t perf_callchain_kernel_p;

int load_allsyms(void);
struct file *perf_event_get(unsigned int fd);
int perf_event_read_local(struct perf_event *event, u64 *value, u64 *enabled, u64 *running);


// redefinition with perf_event.h
// static inline void perf_sample_data_init(struct perf_sample_data *data,
// 					 u64 addr, u64 period)
// {
// 	/* remaining struct members initialized in perf_prepare_sample() */
// 	data->addr = addr;
// 	data->raw  = NULL;
// 	data->br_stack = NULL;
// 	data->period = period;
// 	data->weight = 0;
// 	data->data_src.val = PERF_MEM_NA;
// 	data->txn = 0;
// }

void perf_event_output(struct perf_event *event,
				struct perf_sample_data *data,
				struct pt_regs *regs);

#endif
