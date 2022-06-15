# 1 clcc
&emsp;clcc与pylcc原理基本一致，不同的是开发语言为C语言，属于静态语言版本，适用于bpf.c程序比较固定的场景

## 1.1 准备工作

基本要求

- 能力要求：熟悉c，libpf开发特性，
- python2.7 或者python3，coolbpf >=0.1.1，可以执行pip install -U coolbpf
- 环境要求：可以访问pylcc.openanolis.cn或自己建远程编译服务
- 编译要求：本地已安装gcc/make

## 1.2 coolbpf 命令说明

```bash
optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  set file to compile.
  -e ENV, --env ENV     set compile env.
  -a ARCH, --arch ARCH  set architecture.
  -v VER, --version VER
                        set kernel version.
  -i INC, --include INC
                        set include path.
  -o, --obj             compile object file only.
```
&emsp;如要将hello.bpf.c 编译成hello.so，执行：

```bash
coolbpf -f hello.bpf.c
```

&emsp;编译成 hello.bpf.o，执行：

```bash
coolbpf -f hello.bpf.c -o
```


## 1.3 验证过程
&emsp;参考pylcc 6.3的例程，先clone 代码 make：

```bash
git clone git@github.com:aliyun/coolbpf.git
cd lcc/clcc/remote/
make
```

&emsp;执行完编译后，就能编译出对应的可执行程序和对应的so，可以在对应路径下逐一验证，功能实现与pylcc实现一致。

### 1.2.1 hello
&emsp;实现和验证流程参考 pylcc hello的验证，实现了hello world 打印功能

### 1.2.2 event_out
&emsp;实现和验证流程参考 pylcc eventOut的验证，实现了往用户态吐数据功能

### 1.2.3 hash_map
&emsp;实现和验证流程参考 pylcc hashMaps的验证，实现了maps数据读取功能

### 1.2.3 call_stack
&emsp;实现和验证流程参考 pylcc callStack的验证，实现了打印内核调用栈功能

## 1.3 clcc 头文件说明
&emsp;头文件clcc.h保存在 include 路径下， 实现了so加载的主要功能，主要功能如下：

### 1.3.1 直接API

```C
/*
 * function name: clcc_init
 * description: load an so
 * arg1: so path to load
 * return: struct clcc_struct *
 */
struct clcc_struct* clcc_init(const char* so_path);

/*
 * function name: clcc_deinit
 * description: release an so
 * arg1:  struct clcc_struct *p; mem will free this function.
 * return: None
 */
struct clcc_struct* clcc_deinit(const char* so_path);

/*
 * function name: clcc_get_call_stack
 * description:  get call stack from table and stack id
 * arg1:  table id: from struct clcc_struct get_maps_id function.
 * arg2: stack_id: from bpf kernel bpf_get_stackid function.
 * arg3: pstack:  struct clcc_call_stack, should be alloced at first, use in clcc_print_stack
 * arg4: pclcc: setup from clcc_init function
 * return: 0 if success.
 */
int clcc_get_call_stack(int table_id,
                               int stack_id,
                               struct clcc_call_stack *pstack,
                               struct clcc_struct *pclcc)
                       
 
/*
 * function name: clcc_print_stack
 * description:  print call stack
 * arg1: pstack:  struct clcc_call_stack, stack to print, setup from clcc_get_call_stack.
 * arg2: pclcc: setup from clcc_init function
 * return: None.
 */
void clcc_print_stack(struct clcc_call_stack *pstack,
                             struct clcc_struct *pclcc)
                                                         
```

### 1.3.2 结构体API
&emsp; struct clcc_struct 是 clcc 最重要的结构体，封装libbpf的主要功能，结构定义如下：

```C
struct clcc_struct{
    /*
     * member: handle
     * description: so file file handle pointer, it should not be modified or accessed.
     */
    void* handle;
    /*
     * member: status
     * description: reserved.
     */
    int status;
    /*
     * member: init
     * description: install libbpf programme, 
     * arg1: print level, 0~3. -1:do not print any thing.
     * return: 0 if success.
     */
    int  (*init)(int);
     /*
     * member: exit
     * description: uninstall libbpf programme, 
     * return: None.
     */
    void (*exit)(void);
    /*
     * member: get_maps_id
     * description: get map id from map name which quote in LBC_XXX().
     * arg1: event: map name which quote in LBC_XXX(), eg: LBC_PERF_OUTPUT(e_out, struct data_t, 128),  then arg is e_out.
     * return: >=0, failed when < 0 
     */
    int  (*get_maps_id)(char* event);
    /*
     * member: set_event_cb
     * description: set call back function for perf out event.
     * arg1: event id, get from get_maps_id.
     * arg2: callback function when event polled.
     * arg3: lost callback function when event polled.
     * return: 0 if success.
     */
    int  (*set_event_cb)(int id,
                       void (*cb)(void *ctx, int cpu, void *data, unsigned int size),
                       void (*lost)(void *ctx, int cpu, unsigned long long cnt));
    /*
     * member: event_loop
     * description: poll perf out put event, usually used in pairs with set_event_cb function.
     * arg1: event id, get from get_maps_id.
     * arg2: timeout， unit seconds. -1 nevet timeout.
     * return: 0 if success.
     */    
    int  (*event_loop)(int id, int timeout);
    /*
     * member: map_lookup_elem
     * description: lookup element by key.
     * arg1: event id, get from get_maps_id.
     * arg2: key point.
     * arg3: value point.
     * return: 0 if success.
     */    
    int  (*map_lookup_elem)(int id, const void *key, void *value);
    /*
     * member: map_lookup_and_delete_elem
     * description: lookup element by key then delete key.
     * arg1: event id, get from get_maps_id.
     * arg2: key point.
     * arg3: value point.
     * return: 0 if success.
     */    
    int  (* map_delete_elem)(int id, const void *key, void *value);
    /*
     * member: map_lookup_and_delete_elem
     * description: lookup element by key then delete key.
     * arg1: event id, get from get_maps_id.
     * arg2: key point.
     * return: 0 if success.
     */    
    int  (*map_delete_elem)(int id, const void *key);
    /*
     * member: map_get_next_key
     * description: walk keys from maps.
     * arg1: event id, get from get_maps_id.
     * arg2: key point.
     * arg3: next key point.
     * return: 0 if success.
     */   
    int  (*map_get_next_key)(int id, const void *key, void *next_key);
    const char* (*get_map_types)(void);
    /*
     * member: ksym_search
     * description: get symbol from kernel addr.
     * arg1: kernnel addr.
     * return: symbol name and address information.
     */   
    struct ksym* (*ksym_search)(unsigned long addr);
};
```
