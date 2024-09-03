BTF（BPF Type Format）是一种类似于DWARF的格式，专用于描述程序中数据类型。

如下图所示，elf文件中.BTF段由三部分构成，分别是头部、type数据和string数据。下面也依据这三部分介绍BTF。

![](https://intranetproxy.alipay.com/skylark/lark/0/2021/png/15256992/1622337437059-7080e42d-8d88-42c6-966e-07db2ac0da5e.png)

## BTF头部
BTF头部的格式如下。关键参数是：

1. type_off和type_len描述了type array；
2. str_off和str_len描述了string array。

```c
struct btf_header {
    __u16   magic;			// 0xeB9F
    __u8    version;		
    __u8    flags;
    __u32   hdr_len;		// = sizeof(struct btf_header)
    /* All offsets are in bytes relative to the end of this header */
    __u32   type_off;       /* offset of type section       */
    __u32   type_len;       /* length of type section       */
    __u32   str_off;        /* offset of string section     */
    __u32   str_len;        /* length of string section     */
};
```

## BTF types数据
BTF types数据部分记录了程序中的每个BTF类型。本节将从三部分介绍，分别是：1）16个BTF类型概述；2）BTF类型公有信息部分；3）BTF类型私有信息部分。

### BTF类型
这些类型大致可以分为三类：

1. 基本类型：BTF_KIND_INT、BTF_KIND_ENUM、BTF_KIND_FWD（前向声明）和BTF_KIND_FLOAT；
2. 非引用类型：包含基本类型、BTF_KIND_STRUCT和BTF_KIND_UNION。
3. 引用类型：BTF_KIND_CONST、BTF_KIND_VOLATILE、BTF_KIND_RESTRICT、BTF_KIND_PTR 、BTF_KIND_TYPEDEF、BTF_KIND_FUNC、BTF_KIND_ARRAY和BTF_KIND_FUNC_PROTO；



划分依据主要依赖于BTF去重算法，BTF去重算法大致可分为三个阶段。第一阶段实现基本类型的去重，只需要简单比较type信息；第二阶段是非引用类型去重（不包括基本类型），较为复杂，需要考虑环和前向声明问题；第三阶段就是引用类型去重，因为引用类型去重主要是判断所引用的非引用类型是否相等，而且非引用类型在第一第二阶段已经完成去重，所以这一阶段相对而言要简单很多。具体可以参考两篇文章：[Enhancing the Linux kernel with BTF type information](https://facebookmicrosites.github.io/bpf/blog/2018/11/14/btf-enhancement.html)和探秘libbpf及展望lcc。

```c
#define BTF_KIND_INT            1       /* Integer      */
#define BTF_KIND_PTR            2       /* Pointer      */
#define BTF_KIND_ARRAY          3       /* Array        */
#define BTF_KIND_STRUCT         4       /* Struct       */
#define BTF_KIND_UNION          5       /* Union        */
#define BTF_KIND_ENUM           6       /* Enumeration  */
#define BTF_KIND_FWD            7       /* Forward      */
#define BTF_KIND_TYPEDEF        8       /* Typedef      */
#define BTF_KIND_VOLATILE       9       /* Volatile     */
#define BTF_KIND_CONST          10      /* Const        */
#define BTF_KIND_RESTRICT       11      /* Restrict     */
#define BTF_KIND_FUNC           12      /* Function     */
#define BTF_KIND_FUNC_PROTO     13      /* Function Proto       */
#define BTF_KIND_VAR            14      /* Variable     */
#define BTF_KIND_DATASEC        15      /* Section      */
#define BTF_KIND_FLOAT          16      /* Floating point       */
```

### BTF type公有信息
每个BTF类型都包含一个公共部分：struct btf_type。struct btf_type包含四个关键字段，对于每个字段都给出了详细的解释，并结合具体的实例阐述：

+ name_off：表示该BTF类型对应的名字在string数据内的偏移，比如struct test，其名称是test，偏移则是test在string数据内的偏移；
+ info：记录了BTF类型，以及特殊类型的额外信息，如STRUCT类型，则包含了member的数量；
+ size：当类型是非应用类型时，记录了该类型所占用内存的大小，如struct test，则size = sizeof(struct test)；
+ type：当类型是引用类型时，表示引用的下一个BTF type的type id。

```c
struct btf_type {
	__u32 name_off;
	/* "info" bits arrangement
	 * bits  0-15: vlen (e.g. # of struct's members)
	 * bits 16-23: unused
	 * bits 24-27: kind (e.g. int, ptr, array...etc)
	 * bits 28-30: unused
	 * bit     31: kind_flag, currently used by
	 *             struct, union and fwd
	 */
	__u32 info;
	/* "size" is used by INT, ENUM, STRUCT, UNION and DATASEC.
	 * "size" tells the size of the type it is describing.
	 *
	 * "type" is used by PTR, TYPEDEF, VOLATILE, CONST, RESTRICT,
	 * FUNC, FUNC_PROTO and VAR.
	 * "type" is a type_id referring to another type.
	 */
	union {
		__u32 size;
		__u32 type;
	};
};
```

### BTF type私有信息
每个BTF type除了公有信息部分，可能还会包含私有信息部分。公有信息部分和私有信息部分在type数据内是紧挨着的。下面将介绍比较具有代表性的三个BTF type。

#### BTF_KIND_INT
INT类型，在struct btf_type之后会紧跟着一个u32的字段：VAL。具体可以看下面的描述：

```c
// 表示signedness, char, or bool
#define BTF_INT_ENCODING(VAL)   (((VAL) & 0x0f000000) >> 24)
// 表示bitfield起始位，目前一般都是0
#define BTF_INT_OFFSET(VAL)     (((VAL) & 0x00ff0000) >> 16)
// 表示bitfield的数目，比如int a:4; 那么BTF_INT_BITS = 4
#define BTF_INT_BITS(VAL)       ((VAL)  & 0x000000ff)
```

所以，当判断INT类型是否相等时，除了公有信息的判断，还需要比较u32字段的相等性。

#### BTF_KIND_ARRAY
ARRAY类型在struct btf_type后会跟一个struct btf_array结构体。结合struct btf_array和具体的实例，描述struct btf_array的具体含义。对于struct test t[10]，其struct btf_array各个字段的值是：

1. type = TYPE_ID(struct test)；
2. index_type = TYPE_ID(int)、TYPE_ID(unsigned int)等都是可以的；
3. nelems = 10。

```c
struct btf_array {
    __u32   type;		// 数组元素的类型，即type id
    __u32   index_type; // 索引类型的type id，该类型一定属于INT，
    __u32   nelems;		// 数组元素的数量
};
```

#### BTF_KIND_STRUCT
STRUCT类型在struct btf_type后会跟着vlen（见struct btf_type info字段）个struct btf_member。struct btf_member的解释如下：

```c
struct btf_member {
    __u32   name_off;   // 同struct btf_type的name_off
    __u32   type;		// member的type id
    __u32   offset;		// member在结构体内偏移
};
```

## BTF string数据
BTF string数据包含了BTF type使用的所有字符串，使得BTF type可以采用name_off的方式记录自身的名字。

## 参考链接
1. BPF Type Format (BTF)：[https://www.kernel.org/doc/html/latest/bpf/btf.html](https://www.kernel.org/doc/html/latest/bpf/btf.html)
2. libbpf源码：[https://github.com/libbpf/libbpf](https://github.com/libbpf/libbpf)
3. BTF去重算法：[https://facebookmicrosites.github.io/bpf/blog/2018/11/14/btf-enhancement.html](https://facebookmicrosites.github.io/bpf/blog/2018/11/14/btf-enhancement.html)

