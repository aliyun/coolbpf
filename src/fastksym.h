//
// Created by 廖肇燕 on 2022/12/18.
//

#ifndef FASTKSYM_FASTKSYM_H
#define FASTKSYM_FASTKSYM_H

typedef unsigned long addr_t;

struct ksym_cell {
    addr_t addr;
    char func[64];
    char module[31];
    char type;
};

int ksym_setup(int stack_only);
struct ksym_cell* ksym_search(addr_t key);

#endif //FASTKSYM_FASTKSYM_H
