
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "btfparse.h"

#define DEBUG 0

#define pr_dbg(fmt, ...)                          \
    do                                            \
    {                                             \
        if (DEBUG)                                \
            printf("DEBUG: " fmt, ##__VA_ARGS__); \
    } while (0)

static bool btf_type_is_modifier(const struct btf_type *t)
{
    /* Some of them is not strictly a C modifier
     * but they are grouped into the same bucket
     * for BTF concern:
     *   A type (t) that refers to another
     *   type through t->type AND its size cannot
     *   be determined without following the t->type.
     *
     * ptr does not fall into this bucket
     * because its size is always sizeof(void *).
     */
    switch (BTF_INFO_KIND(t->info))
    {
    case BTF_KIND_TYPEDEF:
    case BTF_KIND_VOLATILE:
    case BTF_KIND_CONST:
    case BTF_KIND_RESTRICT:
        // case BTF_KIND_TYPE_TAG:
        return true;
    }

    return false;
}

const struct btf_type *btf_type_skip_modifiers(const struct btf *btf,
                                               uint32_t id, uint32_t *res_id)
{
    const struct btf_type *t = btf__type_by_id(btf, id);

    while (btf_type_is_modifier(t))
    {
        id = t->type;
        t = btf__type_by_id(btf, t->type);
    }

    if (res_id)
        *res_id = id;

    return t;
}

const struct btf_type *btf_type_skip_ptr(const struct btf *btf, uint32_t id)
{
    const struct btf_type *t = btf__type_by_id(btf, id);
    while (btf_is_ptr(t))
        t = btf__type_by_id(btf, t->type);

    return t;
}

/* Similar to btf_type_skip_modifiers() but does not skip typedefs. */
#if 0
static const struct btf_type *btf_type_skip_qualifiers(const struct btf *btf,
                                                       uint32_t id)
{
    const struct btf_type *t = btf__type_by_id(btf, id);

    while (btf_type_is_modifier(t) &&
           BTF_INFO_KIND(t->info) != BTF_KIND_TYPEDEF)
    {
        t = btf__type_by_id(btf, t->type);
    }

    return t;
}
#endif

// skip modifiers and pointer to find real type
static const struct btf_type *btf_type_find_realtype(struct btf *btf, int typeid)
{
    const struct btf_type *t;
    t = btf__type_by_id(btf, typeid);
    while (btf_type_is_modifier(t) || btf_is_ptr(t))
    {
        t = btf_type_skip_modifiers(btf, typeid, (uint32_t *)&typeid);
        t = btf_type_skip_ptr(btf, typeid);
    }
    return t;
}

const struct btf_member *btf_find_member(struct btf *btf, int typeid,
                                         const char *target_member_name, int *offset)
{
    const struct btf_type *t;
    const struct btf_member *m, *tmpm;
    const char *name;
    int i;

    t = btf_type_find_realtype(btf, typeid);
    m = btf_members(t);
    for (i = 0; i < btf_vlen(t); i++, m++)
    {
        name = btf__name_by_offset(btf, m->name_off);
        if (!name || !name[0])
        {
            // find embedded struct/union
            tmpm = btf_find_member(btf, m->type, target_member_name, offset);
            if (tmpm)
            {
                pr_dbg("find member: name-%s, off-%u, size-%llu\n", btf__name_by_offset(btf, tmpm->name_off), tmpm->offset, btf__resolve_size(btf, tmpm->type));
                *offset += m->offset;
                return tmpm;
            }
        }
        else if (strcmp(name, target_member_name) == 0)
        {
            pr_dbg("find member: name-%s, off-%u, size-%llu\n", btf__name_by_offset(btf, m->name_off), m->offset, btf__resolve_size(btf, m->type));
            *offset += m->offset;
            return m;
        }
    }

    pr_dbg("Unable to find %s(member) in %s(struct)\n", target_member_name, btf__name_by_offset(btf, t->name_off));
    return NULL;
}

struct btf *btf_load(char *btf_custom_path)
{
    struct btf *btf;
    int err;
    if (btf_custom_path != NULL)
        btf = btf__parse(btf_custom_path, NULL);
    else
        btf = libbpf_find_kernel_btf();

    err = libbpf_get_error(btf);
    if (err)
    {
        errno = -err;
        return NULL;
    }

    return btf;
}

struct member_attribute *btf_find_struct_member(struct btf *btf, char *struct_name, char *member_name)
{
    int typeid, offset;
    struct member_attribute *ma = NULL;
    const struct btf_member *member;

    if (!btf || !struct_name || !member_name)
    {
        errno = EINVAL;
        return NULL;
    }

    ma = malloc(sizeof(struct member_attribute));
    if (!ma)
    {
        errno = ENOMEM;
        return NULL;
    }

    typeid = btf__find_by_name_kind(btf, struct_name, BTF_KIND_STRUCT);
    if (typeid < 0)
    {
        errno = EINVAL;
        goto free_ma;
    }

    offset = 0;
    member = btf_find_member(btf, typeid, member_name, &offset);
    if (!member)
    {
        pr_dbg("failed to find member: %s in struct: %s, err = %d\n", member_name, btf__name_by_offset(btf, btf__type_by_id(btf, typeid)->name_off), -errno);
        goto free_ma;
    }

    ma->offset = offset;
    ma->size = btf__resolve_size(btf, member->type);
    ma->real_size = btf_type_find_realtype(btf, member->type)->size;
    return ma;

free_ma:
    return NULL;
}
