/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include "linux/config.h"
#include "linux/bpf.h"
// #include <linux/bpf_trace.h>
// #include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mmzone.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/license.h>
#include "linux/filter.h"
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/idr.h>
#include <linux/cred.h>
// #include <linux/timekeeping.h>
#include <linux/ctype.h>
#include <linux/nospec.h>

#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/sched.h>

#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "ebpf.h"

#include "allsyms.h"
#include "ebpf_kprobe.h"
#include "ebpf_tracepoint.h"

MODULE_LICENSE("Dual BSD/GPL");

static int dev_major = 0;
static struct class *ebpf_class = NULL;
static struct cdev ebpfdev;

#define FMODE_CAN_READ   FMODE_READ
#define FMODE_CAN_WRITE  FMODE_WRITE

#define IS_FD_ARRAY(map) ((map)->map_type == BPF_MAP_TYPE_PROG_ARRAY || \
			   (map)->map_type == BPF_MAP_TYPE_PERF_EVENT_ARRAY || \
			   (map)->map_type == BPF_MAP_TYPE_CGROUP_ARRAY || \
			   (map)->map_type == BPF_MAP_TYPE_ARRAY_OF_MAPS)
#define IS_FD_HASH(map) ((map)->map_type == BPF_MAP_TYPE_HASH_OF_MAPS)
#define IS_FD_MAP(map) (IS_FD_ARRAY(map) || IS_FD_HASH(map))

DEFINE_PER_CPU(int, bpf_prog_active);
static DEFINE_IDR(prog_idr);
static DEFINE_SPINLOCK(prog_idr_lock);
static DEFINE_IDR(map_idr);
static DEFINE_SPINLOCK(map_idr_lock);

static const struct bpf_map_ops * const bpf_map_types[] = {
#define BPF_PROG_TYPE(_id, _ops)
#define BPF_MAP_TYPE(_id, _ops) \
	[_id] = &_ops,
#include "linux/bpf_types.h"
#undef BPF_PROG_TYPE
#undef BPF_MAP_TYPE
};

struct ebpfdrv_attr
{
    uint32_t prog_fd;
    union
    {
        struct
        {
            bool is_return;
            uint64_t name;
        } kprobe;

        struct
        {
            uint64_t category;
            uint64_t name;
        } tracepoint;
    };
};

#define u64_to_user_ptr(x) (          \
	{                                 \
		typecheck(u64, x);            \
		(void __user *)(uintptr_t) x; \
	})

/*
 * If we're handed a bigger struct than we know of, ensure all the unknown bits
 * are 0 - i.e. new user-space does not rely on any kernel feature extensions
 * we don't know about yet.
 *
 * There is a ToCToU between this function call and the following
 * copy_from_user() call. However, this is not a concern since this function is
 * meant to be a future-proofing of bits.
 */
static int check_uarg_tail_zero(void __user *uaddr,
								size_t expected_size,
								size_t actual_size)
{
	unsigned char __user *addr;
	unsigned char __user *end;
	unsigned char val;
	int err;

	if (unlikely(actual_size > PAGE_SIZE)) /* silly large */
		return -E2BIG;

	if (unlikely(!access_ok(VERIFY_READ, uaddr, actual_size)))
		return -EFAULT;

	if (actual_size <= expected_size)
		return 0;

	addr = uaddr + expected_size;
	end = uaddr + actual_size;

	for (; addr < end; addr++)
	{
		err = get_user(val, addr);
		if (err)
			return err;
		if (val)
			return -E2BIG;
	}

	return 0;
}

static struct bpf_map *find_and_alloc_map(union bpf_attr *attr)
{
	const struct bpf_map_ops *ops;
	u32 type = attr->map_type;
	struct bpf_map *map;
	int err;

	if (type >= ARRAY_SIZE(bpf_map_types))
		return ERR_PTR(-EINVAL);
	type = array_index_nospec(type, ARRAY_SIZE(bpf_map_types));
	ops = bpf_map_types[type];
	if (!ops)
		return ERR_PTR(-EINVAL);

	if (ops->map_alloc_check) {
		err = ops->map_alloc_check(attr);
		if (err)
			return ERR_PTR(err);
	}
	map = ops->map_alloc(attr);
	if (IS_ERR(map))
		return map;
	map->ops = ops;
	map->map_type = type;
	return map;
}

/**
 *	__vmalloc_node  -  allocate virtually contiguous memory
 *	@size:		allocation size
 *	@align:		desired alignment
 *	@gfp_mask:	flags for the page level allocator
 *	@prot:		protection mask for the allocated pages
 *	@node:		node to use for allocation or NUMA_NO_NODE
 *	@caller:	caller's return address
 *
 *	Allocate enough pages to cover @size from the page level
 *	allocator with @gfp_mask flags.  Map them into contiguous
 *	kernel virtual space, using a pagetable protection of @prot.
 *
 *	Reclaim modifiers in @gfp_mask - __GFP_NORETRY, __GFP_REPEAT
 *	and __GFP_NOFAIL are not supported
 *
 *	Any use of gfp flags outside of GFP_KERNEL should be consulted
 *	with mm people.
 *
 */
void *__vmalloc_node(unsigned long size, unsigned long align,
			    gfp_t gfp_mask, pgprot_t prot,
			    int node, const void *caller)
{
	return __vmalloc_node_range_p(size, align, VMALLOC_START, VMALLOC_END,
				gfp_mask, prot, node, caller);
}

/*
 * We really want to have this inlined due to caller tracking. This
 * function is used by the highlevel vmalloc apis and so we want to track
 * their callers and inlining will achieve that.
 */
static inline void *__vmalloc_node_flags(unsigned long size,
					int node, gfp_t flags)
{
	return __vmalloc_node(size, 1, flags, PAGE_KERNEL,
					node, __builtin_return_address(0));
}

void *bpf_map_area_alloc(size_t size, int numa_node)
{
	/* We definitely need __GFP_NORETRY, so OOM killer doesn't
	 * trigger under memory pressure as we really just want to
	 * fail instead.
	 */
	const gfp_t flags = __GFP_NOWARN | __GFP_NORETRY | __GFP_ZERO;
	void *area;

	if (size <= (PAGE_SIZE << PAGE_ALLOC_COSTLY_ORDER)) {
		area = kmalloc_node(size, GFP_USER | flags, numa_node);
		if (area != NULL)
			return area;
	}
	return __vmalloc_node_flags(size, numa_node, GFP_KERNEL | flags);
}

void bpf_map_area_free(void *area)
{
	kvfree(area);
}

void bpf_map_init_from_attr(struct bpf_map *map, union bpf_attr *attr)
{
	map->map_type = attr->map_type;
	map->key_size = attr->key_size;
	map->value_size = attr->value_size;
	map->max_entries = attr->max_entries;
	map->map_flags = attr->map_flags;
	map->numa_node = bpf_map_attr_numa_node(attr);
}

int bpf_map_precharge_memlock(u32 pages)
{
	struct user_struct *user = get_current_user();
	unsigned long memlock_limit, cur;

	memlock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	cur = atomic_long_read(&user->locked_vm);
	free_uid_p(user);
	if (cur + pages > memlock_limit)
		return -EPERM;
	return 0;
}

static int bpf_charge_memlock(struct user_struct *user, u32 pages)
{
	unsigned long memlock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	if (atomic_long_add_return(pages, &user->locked_vm) > memlock_limit) {
		atomic_long_sub(pages, &user->locked_vm);
		return -EPERM;
	}
	return 0;
}

static void bpf_uncharge_memlock(struct user_struct *user, u32 pages)
{
	atomic_long_sub(pages, &user->locked_vm);
}

static int bpf_map_init_memlock(struct bpf_map *map)
{
	struct user_struct *user = get_current_user();
	int ret;

	ret = bpf_charge_memlock(user, map->pages);
	if (ret) {
		free_uid_p(user);
		return ret;
	}
	map->user = user;
	return ret;
}

static void bpf_map_release_memlock(struct bpf_map *map)
{
	struct user_struct *user = map->user;
	bpf_uncharge_memlock(user, map->pages);
	free_uid_p(user);
}

int bpf_map_charge_memlock(struct bpf_map *map, u32 pages)
{
	int ret;

	ret = bpf_charge_memlock(map->user, pages);
	if (ret)
		return ret;
	map->pages += pages;
	return ret;
}

void bpf_map_uncharge_memlock(struct bpf_map *map, u32 pages)
{
	bpf_uncharge_memlock(map->user, pages);
	map->pages -= pages;
}

static int bpf_map_alloc_id(struct bpf_map *map)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock_bh(&map_idr_lock);
	id = idr_alloc_cyclic(&map_idr, map, 1, INT_MAX, GFP_ATOMIC);
	if (id > 0)
		map->id = id;
	spin_unlock_bh(&map_idr_lock);
	idr_preload_end();

	if (WARN_ON_ONCE(!id))
		return -ENOSPC;

	return id > 0 ? 0 : id;
}

static void bpf_map_free_id(struct bpf_map *map, bool do_idr_lock)
{
	unsigned long flags;

	if (do_idr_lock)
		spin_lock_irqsave(&map_idr_lock, flags);
	else
		__acquire(&map_idr_lock);

	idr_remove(&map_idr, map->id);

	if (do_idr_lock)
		spin_unlock_irqrestore(&map_idr_lock, flags);
	else
		__release(&map_idr_lock);
}

/* called from workqueue */
static void bpf_map_free_deferred(struct work_struct *work)
{
	struct bpf_map *map = container_of(work, struct bpf_map, work);

	bpf_map_release_memlock(map);
	// security_bpf_map_free(map);
	/* implementation dependent freeing */
	map->ops->map_free(map);
}

static void bpf_map_put_uref(struct bpf_map *map)
{
	if (atomic_dec_and_test(&map->usercnt)) {
		if (map->map_type == BPF_MAP_TYPE_PROG_ARRAY)
			bpf_fd_array_map_clear(map);
	}
}

/* decrement map refcnt and schedule it for freeing via workqueue
 * (unrelying map implementation ops->map_free() might sleep)
 */
static void __bpf_map_put(struct bpf_map *map, bool do_idr_lock)
{
	if (atomic_dec_and_test(&map->refcnt)) {
		/* bpf_map_free_id() must be called first */
		bpf_map_free_id(map, do_idr_lock);
		INIT_WORK(&map->work, bpf_map_free_deferred);
		schedule_work(&map->work);
	}
}

void bpf_map_put(struct bpf_map *map)
{
	__bpf_map_put(map, true);
}

void bpf_map_put_with_uref(struct bpf_map *map)
{
	bpf_map_put_uref(map);
	bpf_map_put(map);
}

static int bpf_map_release(struct inode *inode, struct file *filp)
{
	struct bpf_map *map = filp->private_data;

	if (map->ops->map_release)
		map->ops->map_release(map, filp);

	bpf_map_put_with_uref(map);
	return 0;
}

#ifdef CONFIG_PROC_FS
static int bpf_map_show_fdinfo(struct seq_file *m, struct file *filp)
{
	const struct bpf_map *map = filp->private_data;
	const struct bpf_array *array;
	u32 owner_prog_type = 0;
	u32 owner_jited = 0;
	int ret;

	if (map->map_type == BPF_MAP_TYPE_PROG_ARRAY) {
		array = container_of(map, struct bpf_array, map);
		owner_prog_type = array->owner_prog_type;
		owner_jited = array->owner_jited;
	}

	ret = seq_printf(m,
		   "map_type:\t%u\n"
		   "key_size:\t%u\n"
		   "value_size:\t%u\n"
		   "max_entries:\t%u\n"
		   "map_flags:\t%#x\n"
		   "memlock:\t%llu\n"
		   "map_id:\t%u\n",
		   map->map_type,
		   map->key_size,
		   map->value_size,
		   map->max_entries,
		   map->map_flags,
		   map->pages * 1ULL << PAGE_SHIFT,
		   map->id);

	if (owner_prog_type) {
		ret += seq_printf(m, "owner_prog_type:\t%u\n",
				  owner_prog_type);
		ret += seq_printf(m, "owner_jited:\t%u\n",
				  owner_jited);
	}
	return ret;
}
#endif


static ssize_t bpf_dummy_read(struct file *filp, char __user *buf, size_t siz,
			      loff_t *ppos)
{
	/* We need this handler such that alloc_file() enables
	 * f_mode with FMODE_CAN_READ.
	 */
	return -EINVAL;
}

static ssize_t bpf_dummy_write(struct file *filp, const char __user *buf,
			       size_t siz, loff_t *ppos)
{
	/* We need this handler such that alloc_file() enables
	 * f_mode with FMODE_CAN_WRITE.
	 */
	return -EINVAL;
}

const struct file_operations bpf_map_fops = {
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= bpf_map_show_fdinfo,
#endif
	.release	= bpf_map_release,
	.read		= bpf_dummy_read,
	.write		= bpf_dummy_write,
};

int bpf_map_new_fd(struct bpf_map *map, int flags)
{
	// int ret;

	// ret = security_bpf_map(map, OPEN_FMODE(flags));
	// if (ret < 0)
	// 	return ret;

	return anon_inode_getfd("bpf-map", &bpf_map_fops, map,
				flags | O_CLOEXEC);
}

int bpf_get_file_flag(int flags)
{
	if ((flags & BPF_F_RDONLY) && (flags & BPF_F_WRONLY))
		return -EINVAL;
	if (flags & BPF_F_RDONLY)
		return O_RDONLY;
	if (flags & BPF_F_WRONLY)
		return O_WRONLY;
	return O_RDWR;
}

/* helper macro to check that unused fields 'union bpf_attr' are zero */
#define CHECK_ATTR(CMD) \
	memchr_inv((void *) &attr->CMD##_LAST_FIELD + \
		   sizeof(attr->CMD##_LAST_FIELD), 0, \
		   sizeof(*attr) - \
		   offsetof(union bpf_attr, CMD##_LAST_FIELD) - \
		   sizeof(attr->CMD##_LAST_FIELD)) != NULL

/* dst and src must have at least BPF_OBJ_NAME_LEN number of bytes.
 * Return 0 on success and < 0 on error.
 */
static int bpf_obj_name_cpy(char *dst, const char *src)
{
	const char *end = src + BPF_OBJ_NAME_LEN;

	memset(dst, 0, BPF_OBJ_NAME_LEN);

	/* Copy all isalnum() and '_' char */
	while (src < end && *src) {
		if (!isalnum(*src) && *src != '_')
			return -EINVAL;
		*dst++ = *src++;
	}

	/* No '\0' found in BPF_OBJ_NAME_LEN number of bytes */
	if (src == end)
		return -EINVAL;

	return 0;
}

#define BPF_MAP_CREATE_LAST_FIELD map_name
static int map_create(union bpf_attr *attr)
{
	int numa_node = bpf_map_attr_numa_node(attr);
	struct bpf_map *map;
	int f_flags;
	int err;

	err = CHECK_ATTR(BPF_MAP_CREATE);
	if (err)
		return -EINVAL;

	f_flags = bpf_get_file_flag(attr->map_flags);
	if (f_flags < 0)
		return f_flags;

	if (numa_node != NUMA_NO_NODE &&
	    ((unsigned int)numa_node >= nr_node_ids ||
	     !node_online(numa_node)))
		return -EINVAL;

	/* find map type and init map: hashtable vs rbtree vs bloom vs ... */
	map = find_and_alloc_map(attr);
	if (IS_ERR(map))
		return PTR_ERR(map);

	err = bpf_obj_name_cpy(map->name, attr->map_name);
	if (err)
		goto free_map_nouncharge;

	atomic_set(&map->refcnt, 1);
	atomic_set(&map->usercnt, 1);

	// err = security_bpf_map_alloc(map);
	// if (err)
	// 	goto free_map_nouncharge;

	err = bpf_map_init_memlock(map);
	if (err)
		goto free_map_sec;

	err = bpf_map_alloc_id(map);
	if (err)
		goto free_map;

	err = bpf_map_new_fd(map, f_flags);
	if (err < 0) {
		/* failed to allocate fd.
		 * bpf_map_put() is needed because the above
		 * bpf_map_alloc_id() has published the map
		 * to the userspace and the userspace may
		 * have refcnt-ed it through BPF_MAP_GET_FD_BY_ID.
		 */
		bpf_map_put(map);
		return err;
	}

	return err;

free_map:
	bpf_map_release_memlock(map);
free_map_sec:
	// security_bpf_map_free(map);
free_map_nouncharge:
	map->ops->map_free(map);
	return err;
}

/* if error is returned, fd is released.
 * On success caller should complete fd access with matching fdput()
 */
struct bpf_map *__bpf_map_get(struct fd f)
{
	if (!f.file)
		return ERR_PTR(-EBADF);
	if (f.file->f_op != &bpf_map_fops) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	return f.file->private_data;
}

/* prog's and map's refcnt limit */
#define BPF_MAX_REFCNT 32768

struct bpf_map *bpf_map_inc(struct bpf_map *map, bool uref)
{
	if (atomic_inc_return(&map->refcnt) > BPF_MAX_REFCNT) {
		atomic_dec(&map->refcnt);
		return ERR_PTR(-EBUSY);
	}
	if (uref)
		atomic_inc(&map->usercnt);
	return map;
}

struct bpf_map *bpf_map_get_with_uref(u32 ufd)
{
	struct fd f = fdget(ufd);
	struct bpf_map *map;

	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return map;

	map = bpf_map_inc(map, true);
	fdput(f);

	return map;
}

/* map_idr_lock should have been held */
static struct bpf_map *bpf_map_inc_not_zero(struct bpf_map *map,
					    bool uref)
{
	int refold;

	refold = __atomic_add_unless(&map->refcnt, 1, 0);

	if (refold >= BPF_MAX_REFCNT) {
		__bpf_map_put(map, false);
		return ERR_PTR(-EBUSY);
	}

	if (!refold)
		return ERR_PTR(-ENOENT);

	if (uref)
		atomic_inc(&map->usercnt);

	return map;
}

int __weak bpf_stackmap_copy(struct bpf_map *map, void *key, void *value)
{
	return -ENOTSUPP;
}

/* last field in 'union bpf_attr' used by this command */
#define BPF_MAP_LOOKUP_ELEM_LAST_FIELD value

static int map_lookup_elem(union bpf_attr *attr)
{
	void __user *ukey = u64_to_user_ptr(attr->key);
	void __user *uvalue = u64_to_user_ptr(attr->value);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	void *key, *value, *ptr;
	u32 value_size;
	struct fd f;
	int err;

	if (CHECK_ATTR(BPF_MAP_LOOKUP_ELEM))
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);

	if (!(f.file->f_mode & FMODE_CAN_READ)) {
		err = -EPERM;
		goto err_put;
	}

	key = memdup_user(ukey, map->key_size);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto err_put;
	}

	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
		value_size = round_up(map->value_size, 8) * num_possible_cpus();
	else if (IS_FD_MAP(map))
		value_size = sizeof(u32);
	else
		value_size = map->value_size;

	err = -ENOMEM;
	value = kmalloc(value_size, GFP_USER | __GFP_NOWARN);
	if (!value)
		goto free_key;

	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH) {
		err = -EACCES;
		err = bpf_percpu_hash_copy(map, key, value);
	} else if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		err = -EACCES;
		// err = bpf_percpu_array_copy(map, key, value);
	} else if (map->map_type == BPF_MAP_TYPE_STACK_TRACE) {
		err = -EACCES;
		// err = bpf_stackmap_copy(map, key, value);
	} else if (IS_FD_ARRAY(map)) {
		rcu_read_lock();
		err = bpf_fd_array_map_update_elem(map, f.file, key, value,
						   attr->flags);
		rcu_read_unlock();
	} else if (IS_FD_HASH(map)) {
		err = -EACCES;
	} else {
		rcu_read_lock();
		ptr = map->ops->map_lookup_elem(map, key);
		if (ptr)
			memcpy(value, ptr, value_size);
		rcu_read_unlock();
		err = ptr ? 0 : -ENOENT;
	}

	if (err)
		goto free_value;

	err = -EFAULT;
	if (copy_to_user(uvalue, value, value_size) != 0)
		goto free_value;

	err = 0;

free_value:
	kfree(value);
free_key:
	kfree(key);
err_put:
	fdput(f);
	return err;
}

#define BPF_MAP_UPDATE_ELEM_LAST_FIELD flags

static int map_update_elem(union bpf_attr *attr)
{
	void __user *ukey = u64_to_user_ptr(attr->key);
	void __user *uvalue = u64_to_user_ptr(attr->value);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	void *key, *value;
	u32 value_size;
	struct fd f;
	int err;

	if (CHECK_ATTR(BPF_MAP_UPDATE_ELEM))
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);

	if (!(f.file->f_mode & FMODE_CAN_WRITE)) {
		err = -EPERM;
		goto err_put;
	}

	key = memdup_user(ukey, map->key_size);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto err_put;
	}

	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY)
		value_size = round_up(map->value_size, 8) * num_possible_cpus();
	else
		value_size = map->value_size;

	err = -ENOMEM;
	value = kmalloc(value_size, GFP_USER | __GFP_NOWARN);
	if (!value)
		goto free_key;

	err = -EFAULT;
	if (copy_from_user(value, uvalue, value_size) != 0)
		goto free_value;

	/* must increment bpf_prog_active to avoid kprobe+bpf triggering from
	 * inside bpf map update or delete otherwise deadlocks are possible
	 */
	preempt_disable();
	__this_cpu_inc(bpf_prog_active);
	if (map->map_type == BPF_MAP_TYPE_PERCPU_HASH ||
	    map->map_type == BPF_MAP_TYPE_LRU_PERCPU_HASH) {
		err = -EACCES;
		err = bpf_percpu_hash_update(map, key, value, attr->flags);
	} else if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		err = -EACCES;
		// err = bpf_percpu_array_update(map, key, value, attr->flags);
	} else if (IS_FD_ARRAY(map)) {
		rcu_read_lock();
		err = bpf_fd_array_map_update_elem(map, f.file, key, value,
						   attr->flags);
		rcu_read_unlock();
	} else if (map->map_type == BPF_MAP_TYPE_HASH_OF_MAPS) {
		err = -EACCES;
		// rcu_read_lock();
		// err = bpf_fd_htab_map_update_elem(map, f.file, key, value,
		// 				  attr->flags);
		// rcu_read_unlock();
	} else {
		rcu_read_lock();
		err = map->ops->map_update_elem(map, key, value, attr->flags);
		rcu_read_unlock();
	}
	__this_cpu_dec(bpf_prog_active);
	preempt_enable();
free_value:
	kfree(value);
free_key:
	kfree(key);
err_put:
	fdput(f);
	return err;
}

#define BPF_MAP_DELETE_ELEM_LAST_FIELD key

static int map_delete_elem(union bpf_attr *attr)
{
	void __user *ukey = u64_to_user_ptr(attr->key);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	struct fd f;
	void *key;
	int err;

	if (CHECK_ATTR(BPF_MAP_DELETE_ELEM))
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);

	if (!(f.file->f_mode & FMODE_CAN_WRITE)) {
		err = -EPERM;
		goto err_put;
	}

	key = memdup_user(ukey, map->key_size);
	if (IS_ERR(key)) {
		err = PTR_ERR(key);
		goto err_put;
	}

	preempt_disable();
	__this_cpu_inc(bpf_prog_active);
	rcu_read_lock();
	err = map->ops->map_delete_elem(map, key);
	rcu_read_unlock();
	__this_cpu_dec(bpf_prog_active);
	preempt_enable();
	kfree(key);
err_put:
	fdput(f);
	return err;
}

/* last field in 'union bpf_attr' used by this command */
#define BPF_MAP_GET_NEXT_KEY_LAST_FIELD next_key

static int map_get_next_key(union bpf_attr *attr)
{
	void __user *ukey = u64_to_user_ptr(attr->key);
	void __user *unext_key = u64_to_user_ptr(attr->next_key);
	int ufd = attr->map_fd;
	struct bpf_map *map;
	void *key, *next_key;
	struct fd f;
	int err;

	if (CHECK_ATTR(BPF_MAP_GET_NEXT_KEY))
		return -EINVAL;

	f = fdget(ufd);
	map = __bpf_map_get(f);
	if (IS_ERR(map))
		return PTR_ERR(map);

	if (!(f.file->f_mode & FMODE_CAN_READ)) {
		err = -EPERM;
		goto err_put;
	}

	if (ukey) {
		key = memdup_user(ukey, map->key_size);
		if (IS_ERR(key)) {
			err = PTR_ERR(key);
			goto err_put;
		}
	} else {
		key = NULL;
	}

	err = -ENOMEM;
	next_key = kmalloc(map->key_size, GFP_USER);
	if (!next_key)
		goto free_key;

	rcu_read_lock();
	err = map->ops->map_get_next_key(map, key, next_key);
	rcu_read_unlock();
	if (err)
		goto free_next_key;

	err = -EFAULT;
	if (copy_to_user(unext_key, next_key, map->key_size) != 0)
		goto free_next_key;

	err = 0;

free_next_key:
	kfree(next_key);
free_key:
	kfree(key);
err_put:
	fdput(f);
	return err;
}


static const struct bpf_prog_ops * const bpf_prog_types[] = {
#define BPF_PROG_TYPE(_id, _name) \
	[_id] = & _name ## _prog_ops,
#define BPF_MAP_TYPE(_id, _ops)
#include "linux/bpf_types.h"
#undef BPF_PROG_TYPE
#undef BPF_MAP_TYPE
};

static int find_prog_type(enum bpf_prog_type type, struct bpf_prog *prog)
{
	const struct bpf_prog_ops *ops;

	if (type >= ARRAY_SIZE(bpf_prog_types))
		return -EINVAL;
	type = array_index_nospec(type, ARRAY_SIZE(bpf_prog_types));
	ops = bpf_prog_types[type];
	if (!ops)
		return -EINVAL;

	prog->aux->ops = ops;
	prog->type = type;
	return 0;
}

/* drop refcnt on maps used by eBPF program and free auxilary data */
static void free_used_maps(struct bpf_prog_aux *aux)
{
	int i;

	for (i = 0; i < aux->used_map_cnt; i++)
		bpf_map_put(aux->used_maps[i]);

	kfree(aux->used_maps);
}

int __bpf_prog_charge(struct user_struct *user, u32 pages)
{
	unsigned long memlock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;
	unsigned long user_bufs;

	if (user) {
		user_bufs = atomic_long_add_return(pages, &user->locked_vm);
		if (user_bufs > memlock_limit) {
			atomic_long_sub(pages, &user->locked_vm);
			return -EPERM;
		}
	}

	return 0;
}

void __bpf_prog_uncharge(struct user_struct *user, u32 pages)
{
	if (user)
		atomic_long_sub(pages, &user->locked_vm);
}

static int bpf_prog_charge_memlock(struct bpf_prog *prog)
{
	struct user_struct *user = get_current_user();
	int ret;

	ret = __bpf_prog_charge(user, prog->pages);
	if (ret) {
		free_uid_p(user);
		return ret;
	}

	prog->aux->user = user;
	return 0;
}

static void bpf_prog_uncharge_memlock(struct bpf_prog *prog)
{
	struct user_struct *user = prog->aux->user;

	__bpf_prog_uncharge(user, prog->pages);
	free_uid_p(user);
}

static int bpf_prog_alloc_id(struct bpf_prog *prog)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock_bh(&prog_idr_lock);
	id = idr_alloc_cyclic(&prog_idr, prog, 1, INT_MAX, GFP_ATOMIC);
	if (id > 0)
		prog->aux->id = id;
	spin_unlock_bh(&prog_idr_lock);
	idr_preload_end();

	/* id is in [1, INT_MAX) */
	if (WARN_ON_ONCE(!id))
		return -ENOSPC;

	return id > 0 ? 0 : id;
}

static void bpf_prog_free_id(struct bpf_prog *prog, bool do_idr_lock)
{
	/* cBPF to eBPF migrations are currently not in the idr store. */
	if (!prog->aux->id)
		return;

	if (do_idr_lock)
		spin_lock_bh(&prog_idr_lock);
	else
		__acquire(&prog_idr_lock);

	idr_remove(&prog_idr, prog->aux->id);

	if (do_idr_lock)
		spin_unlock_bh(&prog_idr_lock);
	else
		__release(&prog_idr_lock);
}

static void __bpf_prog_put_rcu(struct rcu_head *rcu)
{
	struct bpf_prog_aux *aux = container_of(rcu, struct bpf_prog_aux, rcu);

	free_used_maps(aux);
	bpf_prog_uncharge_memlock(aux->prog);
	// security_bpf_prog_free(aux);
	bpf_prog_free(aux->prog);
}

static void __bpf_prog_put(struct bpf_prog *prog, bool do_idr_lock)
{
	if (atomic_dec_and_test(&prog->aux->refcnt)) {
		/* bpf_prog_free_id() must be called first */
		bpf_prog_free_id(prog, do_idr_lock);
		// bpf_prog_kallsyms_del_all(prog);
		call_rcu(&prog->aux->rcu, __bpf_prog_put_rcu);
	}
}

void bpf_prog_put(struct bpf_prog *prog)
{
	__bpf_prog_put(prog, true);
}

static int bpf_prog_release(struct inode *inode, struct file *filp)
{
	struct bpf_prog *prog = filp->private_data;

	bpf_prog_put(prog);
	return 0;
}

#ifdef CONFIG_PROC_FS
static int bpf_prog_show_fdinfo(struct seq_file *m, struct file *filp)
{
	const struct bpf_prog *prog = filp->private_data;
	char prog_tag[sizeof(prog->tag) * 2 + 1] = { };
	int ret = 0;

	// bin2hex(prog_tag, prog->tag, sizeof(prog->tag));
	// ret = seq_printf(m,
	// 	   "prog_type:\t%u\n"
	// 	   "prog_jited:\t%u\n"
	// 	   "prog_tag:\t%s\n"
	// 	   "memlock:\t%llu\n"
	// 	   "prog_id:\t%u\n",
	// 	   prog->type,
	// 	   prog->jited,
	// 	   prog_tag,
	// 	   prog->pages * 1ULL << PAGE_SHIFT,
	// 	   prog->aux->id);

	return ret;
}
#endif

const struct file_operations bpf_prog_fops = {
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= bpf_prog_show_fdinfo,
#endif
	.release	= bpf_prog_release,
	.read		= bpf_dummy_read,
	.write		= bpf_dummy_write,
};

int bpf_prog_new_fd(struct bpf_prog *prog)
{
	// int ret;

	// ret = security_bpf_prog(prog);
	// if (ret < 0)
	// 	return ret;

	return anon_inode_getfd("bpf-prog", &bpf_prog_fops, prog,
				O_RDWR | O_CLOEXEC);
}

static struct bpf_prog *____bpf_prog_get(struct fd f)
{
	if (!f.file)
		return ERR_PTR(-EBADF);
	if (f.file->f_op != &bpf_prog_fops) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	return f.file->private_data;
}

struct bpf_prog *bpf_prog_add(struct bpf_prog *prog, int i)
{
	if (atomic_add_return(i, &prog->aux->refcnt) > BPF_MAX_REFCNT) {
		atomic_sub(i, &prog->aux->refcnt);
		return ERR_PTR(-EBUSY);
	}
	return prog;
}

struct bpf_prog *bpf_prog_inc(struct bpf_prog *prog)
{
	return bpf_prog_add(prog, 1);
}

/* prog_idr_lock should have been held */
struct bpf_prog *bpf_prog_inc_not_zero(struct bpf_prog *prog)
{
	int refold;

	refold = __atomic_add_unless(&prog->aux->refcnt, 1, 0);

	if (refold >= BPF_MAX_REFCNT) {
		__bpf_prog_put(prog, false);
		return ERR_PTR(-EBUSY);
	}

	if (!refold)
		return ERR_PTR(-ENOENT);

	return prog;
}

static struct bpf_prog *__bpf_prog_get(u32 ufd, enum bpf_prog_type *type)
{
	struct fd f = fdget(ufd);
	struct bpf_prog *prog;

	prog = ____bpf_prog_get(f);
	if (IS_ERR(prog))
		return prog;
	if (type && prog->type != *type) {
		prog = ERR_PTR(-EINVAL);
		goto out;
	}

	prog = bpf_prog_inc(prog);
out:
	fdput(f);
	return prog;
}

struct bpf_prog *bpf_prog_get(u32 ufd)
{
	return __bpf_prog_get(ufd, NULL);
}

struct bpf_prog *bpf_prog_get_type(u32 ufd, enum bpf_prog_type type)
{
	return __bpf_prog_get(ufd, &type);
}

static bool is_test_type(enum bpf_prog_type type)
{
	// return bpftest &&
	//        (type == BPF_PROG_TYPE_SOCKET_FILTER ||
	//         type == BPF_PROG_TYPE_SCHED_CLS ||
	//         type == BPF_PROG_TYPE_SCHED_ACT);
	return false;
}

static int
bpf_prog_load_check_attach_type(enum bpf_prog_type prog_type,
				enum bpf_attach_type expected_attach_type)
{
	/* There are currently no prog types that require specifying
	 * attach_type at load time.
	 */
	return 0;
}

struct bpf_tracepoint {
	struct bpf_tracepoint_event *bte;
	struct bpf_prog *prog;
};

static int bpf_tracepoint_release(struct inode *inode, struct file *filp)
{
	struct bpf_tracepoint *bpf_tp = filp->private_data;
	if (bpf_tp->prog) {
		bpf_tracepoint_unregister(bpf_tp->bte, bpf_tp->prog);
		bpf_prog_put(bpf_tp->prog);
	}

	kfree(bpf_tp);
	return 0;
}

static const struct file_operations bpf_tracepoint_fops = {
	.release = bpf_tracepoint_release,
	.read = bpf_dummy_read,
	.write = bpf_dummy_write,
};


struct bpf_kprobe {
	struct bpf_kprobe_event *bke;
	struct bpf_prog *prog;
};

static int bpf_kprobe_release(struct inode *inode, struct file *filp)
{
	struct bpf_kprobe *bpf_kp = filp->private_data;
	if (bpf_kp->prog) {
		bpf_kprobe_unregister(bpf_kp->bke);
		free_bpf_kprobe_event(bpf_kp->bke);
		bpf_prog_put(bpf_kp->prog);
	}

	kfree(bpf_kp);
	return 0;
}

static const struct file_operations bpf_kprobe_fops = {
	.release = bpf_kprobe_release,
	.read = bpf_dummy_read,
	.write = bpf_dummy_write,
};

/* last field in 'union bpf_attr' used by this command */
#define	BPF_PROG_LOAD_LAST_FIELD expected_attach_type

static int bpf_prog_load(union bpf_attr *attr)
{
	enum bpf_prog_type type = attr->prog_type;
	struct bpf_prog *prog;
	int err;
	char license[128];
	bool is_gpl;

	/* RHEL7 - allow only following types */
	if (type != BPF_PROG_TYPE_KPROBE &&
	    type != BPF_PROG_TYPE_TRACEPOINT &&
	    type != BPF_PROG_TYPE_PERF_EVENT &&
	    !is_test_type(type))
		return -EINVAL;

	if (CHECK_ATTR(BPF_PROG_LOAD))
		return -EINVAL;

	if (attr->prog_flags & ~BPF_F_STRICT_ALIGNMENT)
		return -EINVAL;
	/* copy eBPF program license from user space */
	if (strncpy_from_user(license, u64_to_user_ptr(attr->license),
			      sizeof(license) - 1) < 0)
		return -EFAULT;
	license[sizeof(license) - 1] = 0;

	/* eBPF programs must be GPL compatible to use GPL-ed functions */
	is_gpl = license_is_gpl_compatible(license);

	if (attr->insn_cnt == 0 || attr->insn_cnt > BPF_MAXINSNS)
		return -E2BIG;

	if (type == BPF_PROG_TYPE_KPROBE &&
	    attr->kern_version != LINUX_VERSION_CODE)
		return -EINVAL;

	if (type != BPF_PROG_TYPE_SOCKET_FILTER &&
	    type != BPF_PROG_TYPE_CGROUP_SKB &&
	    !capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (bpf_prog_load_check_attach_type(type, attr->expected_attach_type))
		return -EINVAL;

	/* plain bpf_prog allocation */
	prog = bpf_prog_alloc(bpf_prog_size(attr->insn_cnt), GFP_USER);
	if (!prog)
		return -ENOMEM;
	prog->expected_attach_type = attr->expected_attach_type;

	// err = security_bpf_prog_alloc(prog->aux);
	// if (err)
	// 	goto free_prog_nouncharge;

	err = bpf_prog_charge_memlock(prog);
	if (err)
		goto free_prog_sec;

	prog->len = attr->insn_cnt;

	err = -EFAULT;
	if (copy_from_user(prog->insns, u64_to_user_ptr(attr->insns),
			   bpf_prog_insn_size(prog)) != 0)
		goto free_prog;

	prog->orig_prog = NULL;
	prog->jited = 0;

	atomic_set(&prog->aux->refcnt, 1);
	prog->gpl_compatible = is_gpl ? 1 : 0;

	/* find program type: socket_filter vs tracing_filter */
	err = find_prog_type(type, prog);
	if (err < 0)
		goto free_prog;

	// prog->aux->load_time = ktime_get_boot_ns();
	err = bpf_obj_name_cpy(prog->aux->name, attr->prog_name);
	if (err)
		goto free_prog;

	/* run eBPF verifier */
	err = bpf_check(&prog, attr);
	if (err < 0)
		goto free_used_maps;

	/* eBPF program is ready to be JITed */
	if (!prog->bpf_func)
		prog = bpf_prog_select_runtime(prog, &err);
	if (err < 0)
		goto free_used_maps;

	err = bpf_prog_alloc_id(prog);
	if (err)
		goto free_used_maps;

	err = bpf_prog_new_fd(prog);
	if (err < 0) {
		/* failed to allocate fd.
		 * bpf_prog_put() is needed because the above
		 * bpf_prog_alloc_id() has published the prog
		 * to the userspace and the userspace may
		 * have refcnt-ed it through BPF_PROG_GET_FD_BY_ID.
		 */
		bpf_prog_put(prog);
		return err;
	}

	// bpf_prog_kallsyms_add(prog);
	return err;

free_used_maps:
	// bpf_prog_kallsyms_del_subprogs(prog);
	free_used_maps(prog->aux);
free_prog:
	bpf_prog_uncharge_memlock(prog);
free_prog_sec:
	// security_bpf_prog_free(prog->aux);
free_prog_nouncharge:
	bpf_prog_free(prog);
	return err;
}

// #define BPF_PROG_ATTACH_LAST_FIELD attach_flags

static int bpf_prog_attach_kprobe(u32 prog_fd, char *name, bool is_return)
{
	struct bpf_kprobe *bpf_kp;
	struct bpf_prog *prog;
	int kp_fd, err = 0;
	bpf_kp = kzalloc(sizeof(*bpf_kp), GFP_USER);
	if (!bpf_kp)
		return -ENOMEM;

	prog = bpf_prog_get(prog_fd);
	if (IS_ERR(prog)) {
		err = PTR_ERR(prog);
		goto free_bpf_kp;
	}

	bpf_kp->bke = alloc_bpf_kprobe_event(prog, name, is_return);
	if (IS_ERR(bpf_kp->bke)) {
		err = PTR_ERR(bpf_kp->bke);
		goto free_bpf_kp;
	}
	
	err = bpf_kprobe_register(bpf_kp->bke);
	if (err) {
		printk(KERN_ERR "Failed to register kprobe\n");
		goto put_prog;
	}

	bpf_kp->prog = prog;
	kp_fd = anon_inode_getfd("bpf-kprobe", &bpf_kprobe_fops, bpf_kp, O_CLOEXEC);
	if (kp_fd < 0) {
		printk(KERN_ERR "Failed to get anon inode for bpf-kprobe\n");
		bpf_kprobe_unregister(bpf_kp->bke);
		err = kp_fd;
		goto put_prog;
	}
	return kp_fd;

put_prog:
	bpf_prog_put(prog);
free_bke:
	free_bpf_kprobe_event(bpf_kp->bke);
free_bpf_kp:
	kfree(bpf_kp);
	return err;
}

static int bpf_prog_attach_tracepoint(u32 prog_fd, char *category, char *name)
{
	struct bpf_tracepoint *bpf_tp;
	struct bpf_tracepoint_event *bte;
	struct bpf_prog *prog;
	int tp_fd, err = 0;

	bte = bpf_find_tracepoint(name);
	if (!bte)
		return -ENOENT;
	
	bpf_tp = kzalloc(sizeof(*bpf_tp), GFP_USER);
	if (!bpf_tp)
		return -ENOMEM;

	bpf_tp->bte = bte;
	prog = bpf_prog_get(prog_fd);
	if (IS_ERR(prog)) {
		err = PTR_ERR(prog);
		goto free_bpf_tp;
	}

	err = bpf_tracepoint_register(bte, prog);
	if (err)
		goto put_prog;
	
	bpf_tp->prog = prog;
	tp_fd = anon_inode_getfd("bpf-tracepoint", &bpf_tracepoint_fops, bpf_tp, O_CLOEXEC);
	if (tp_fd < 0) {
		bpf_tracepoint_unregister(bpf_tp->bte, prog);
		err = tp_fd;
		goto put_prog;
	}
	return tp_fd;

put_prog:
	bpf_prog_put(prog);
free_bpf_tp:
	kfree(bpf_tp);
	return err;
}

static int bpf_prog_attach(u64 arg)
{
	struct ebpfdrv_attr attr = {};
	struct bpf_prog *prog;
	int err;
	char name[128];
	char category[64];
	u32 prog_fd;

	/* copy attributes from user space, may be less than sizeof(bpf_attr) */
	if (copy_from_user(&attr, u64_to_user_ptr((u64)arg), sizeof(attr)) != 0)
		return -EFAULT;

	prog_fd = attr.prog_fd;
	prog = bpf_prog_get(prog_fd);

	if (IS_ERR(prog))
		return PTR_ERR(prog);
	
	switch(prog->type)
	{
		case BPF_PROG_TYPE_KPROBE:
		{
			if (strncpy_from_user(name, u64_to_user_ptr(attr.kprobe.name), sizeof(name) - 1) < 0)
			{
				err = -EFAULT;
				goto out;
			}
			name[sizeof(name) - 1] = 0;
			err = bpf_prog_attach_kprobe(prog_fd, name, attr.kprobe.is_return);
			break;
		}
		case BPF_PROG_TYPE_TRACEPOINT:
		{
			if (strncpy_from_user(name, u64_to_user_ptr(attr.tracepoint.name), sizeof(name) - 1) < 0)
			{
				err = -EFAULT;
				goto out;
			}
			name[sizeof(name) - 1] = 0;
			
			if (strncpy_from_user(category, u64_to_user_ptr(attr.tracepoint.category), sizeof(category) - 1) < 0)
			{
				err = -EFAULT;
				goto out;
			}
			category[sizeof(category) - 1] = 0;
			err = bpf_prog_attach_tracepoint(prog_fd, category, name);
			break;
		}
		default:
		{
			err = -ENOTSUPP;
			break;
		}
	}

out:
	bpf_prog_put(prog);
	return err;
}

static int bpf_map_get_info_by_fd(struct bpf_map *map,
				  const union bpf_attr *attr,
				  union bpf_attr __user *uattr)
{
	struct bpf_map_info __user *uinfo = u64_to_user_ptr(attr->info.info);
	struct bpf_map_info info = {};
	u32 info_len = attr->info.info_len;
	int err;

	err = check_uarg_tail_zero(uinfo, sizeof(info), info_len);
	if (err)
		return err;
	info_len = min_t(u32, sizeof(info), info_len);

	info.type = map->map_type;
	info.id = map->id;
	info.key_size = map->key_size;
	info.value_size = map->value_size;
	info.max_entries = map->max_entries;
	info.map_flags = map->map_flags;
	memcpy(info.name, map->name, sizeof(map->name));

	if (copy_to_user(uinfo, &info, info_len) ||
	    put_user(info_len, &uattr->info.info_len))
		return -EFAULT;

	return 0;
}

#define BPF_OBJ_GET_INFO_BY_FD_LAST_FIELD info.info

static int bpf_obj_get_info_by_fd(const union bpf_attr *attr,
				  union bpf_attr __user *uattr)
{
	int ufd = attr->info.bpf_fd;
	struct fd f;
	int err;

	if (CHECK_ATTR(BPF_OBJ_GET_INFO_BY_FD))
		return -EINVAL;

	f = fdget(ufd);
	if (!f.file)
		return -EBADFD;

	if (f.file->f_op == &bpf_prog_fops)
		err = -ENOTSUPP;
		// err = bpf_prog_get_info_by_fd(f.file->private_data, attr,
		// 			      uattr);
	else if (f.file->f_op == &bpf_map_fops)
		err = bpf_map_get_info_by_fd(f.file->private_data, attr,
					     uattr);
	else
		err = -EINVAL;

	fdput(f);
	return err;
}

static long ebpf_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	union bpf_attr attr = {};
	static int marked;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!marked)
	{
		mark_tech_preview("eBPF syscall", NULL);
		marked = true;
	}
	
	if (cmd == IOCTL_BPF_PROG_ATTACH)
	{
		err = bpf_prog_attach(arg);
		return err;
	}

	err = check_uarg_tail_zero(u64_to_user_ptr((u64)arg), sizeof(attr), sizeof(attr));
	if (err)
		return err;

	/* copy attributes from user space, may be less than sizeof(bpf_attr) */
	if (copy_from_user(&attr, u64_to_user_ptr((u64)arg), sizeof(attr)) != 0)
		return -EFAULT;

	switch (cmd)
	{
	case IOCTL_BPF_MAP_CREATE:
		printk("IOCTL_BPF_MAP_CREATE\n");
		err = map_create(&attr);
		break;
	case IOCTL_BPF_MAP_LOOKUP_ELEM:
		err = map_lookup_elem(&attr);
		break;
	case IOCTL_BPF_MAP_UPDATE_ELEM:
		err = map_update_elem(&attr);
		break;
	case IOCTL_BPF_MAP_DELETE_ELEM:
		err = map_delete_elem(&attr);
		break;
	case IOCTL_BPF_MAP_GET_NEXT_KEY:
		err = map_get_next_key(&attr);
		break;
	case IOCTL_BPF_PROG_LOAD:
		printk("IOCTL_BPF_PROG_LOAD\n");
		err = bpf_prog_load(&attr);
		printk("IOCTL_BPF_PROG_LOAD return %d\n", err);
		break;
	case IOCTL_BPF_OBJ_GET_INFO_BY_FD:
		err = bpf_obj_get_info_by_fd(&attr, u64_to_user_ptr(arg));
		break;
	default:
		printk("%d not implemented.\n", cmd);
		err = -EINVAL;
		break;
	}

	return err;
}

int ebpf_open(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_cdev;
	return 0;
}

static const struct file_operations ebpf_fops = {
	.unlocked_ioctl = ebpf_ioctl,
	.owner = THIS_MODULE,
	.open = ebpf_open,
};


extern int stack_map_init(void);

static int ebpf_init(void)
{
	int err;
	dev_t devno;

	/* 动态分配设备号 */
	err = alloc_chrdev_region(&devno, 0, 1, "ebpfdev");
	if (err)
		goto out;

	dev_major = MAJOR(devno);
	ebpf_class = class_create(THIS_MODULE, "ebpfdrv");

	/* 初始化cdev结构，并传递file_operations结构指针 */
	cdev_init(&ebpfdev, &ebpf_fops);
	/* 指定所属模块 */
	ebpfdev.owner = THIS_MODULE;
	/* 注册字符设备 */
	err = cdev_add(&ebpfdev, MKDEV(dev_major, 0), 1);
	if (err)
		goto out;

	device_create(ebpf_class, NULL, MKDEV(dev_major, 0), NULL, "ebpfdrv");

	err = load_allsyms();
	if (err)
		goto out;
	stack_map_init();
	return 0;
out:
	printk(KERN_NOTICE "Error %d adding ebpfdev%d\n", err, 0);
	return err;
}
void ebpf_exit(void)
{
	device_destroy(ebpf_class, MKDEV(dev_major, 0));
	class_unregister(ebpf_class);
	class_destroy(ebpf_class);
	cdev_del(&ebpfdev);
	unregister_chrdev_region(MKDEV(dev_major, 0), MINORMASK);
	printk(KERN_INFO "ebpf driver exit\n");
}

module_init(ebpf_init);
module_exit(ebpf_exit);
