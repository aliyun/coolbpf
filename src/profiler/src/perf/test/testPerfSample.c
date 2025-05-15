#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "../perf_sample.h"

int cb(perf_sample_t* sample) {
    if (sample->pid != 0) {
        printf("sample pid: %d, tid: %d, callchain_nr: %ld, user_regs_nr: %ld, stack_size: %ld\n", 
            sample->pid,
            sample->tid,
            sample->callchain_nr,
            sample->user_regs_nr,
            sample->stack_size
        );
    }
}

void testPerf(int loop) {
    int i;
    void *handle = perf_live_on_start(1, cb);
    assert(handle != NULL);
    for (i = 0; i < loop; i ++) {
        sleep(1);
        printf("read perf %d\n", i);
        perf_live_on_read(handle);
    }
    perf_live_on_stop(handle);
}

int main(int argc, char *argv[]) {
    testPerf(4);
    printf("test perf sample ok.\n");
    if (argc > 1) {
        printf("test perf for loop.\n");
        testPerf(atoi(argv[1]));;
    }
    return 0;
}
