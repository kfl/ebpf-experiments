#define _GNU_SOURCE
#include <err.h>
#include <error.h>
#include <errno.h>
#include <stdint.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/unistd_64.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/if_ether.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <bpf/bpf.h>



#include "bpf_insn.h"

int bpf_(int cmd, union bpf_attr *attrs) {
    return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

void array_set(int mapfd, uint32_t key, uint32_t value) {
    union bpf_attr attr = {
        .map_fd = mapfd,
        .key    = (uint64_t)&key,
        .value  = (uint64_t)&value,
        .flags  = BPF_ANY,
    };


    int res = bpf_(BPF_MAP_UPDATE_ELEM, &attr);
    if (res)
        err(1, "map update elem");
}

uint32_t array_get(int map_fd, uint32_t key) {
    uint64_t ret_val;
    union bpf_attr lookup_map = {
      .map_fd = map_fd,
      .key    = (uint64_t)&key,
      .value  = (uint64_t)&ret_val
    };

    int res = bpf_(BPF_MAP_LOOKUP_ELEM, &lookup_map);
    if (res)
        err(1, "map get elem");
    return ret_val;
}



int main(void) {
    union bpf_attr create_map_attrs = {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = 4,
        .value_size = 8,
        .max_entries = 16
    };
    int map_fd = bpf_(BPF_MAP_CREATE, &create_map_attrs);
    if (map_fd == -1)
        err(1, "map create");


    array_set(map_fd, 1, 1);

    int input = 0x42424242;

    char verifier_log[100000];
    struct bpf_insn insns[] = {
        // Load map into r1
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),
        // r0 = 0
        BPF_MOV64_IMM(BPF_REG_0, 0),

        // Make r3 a pointer to the value to write
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -8),
        // Put the value where r3 points to
        BPF_MOV64_IMM(BPF_REG_4, input),
        BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_4, 0),

        // *(r0)-4 = r0
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
        // make r2 a pointer to key, == 0
        // Stack pointer in r2
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        // Adjust it by subbing 4
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),

        /* // Load map into r1  */
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),
        // Set r4 == flags for update_elem
        BPF_MOV64_IMM(BPF_REG_4, BPF_ANY),
        // Call the bpf helper to update the map
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),
        // Exit with 0
        BPF_MOV32_IMM(BPF_REG_0, 0), /* r0 = 0 */
        BPF_EXIT_INSN()
    };
    union bpf_attr create_prog_attrs = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = sizeof(insns) / sizeof(insns[0]),
        .insns = (uint64_t)insns,
        .license = (uint64_t)"",
        .log_level = 2,
        .log_size = sizeof(verifier_log),
        .log_buf = (uint64_t)verifier_log
    };
    int progfd = bpf_(BPF_PROG_LOAD, &create_prog_attrs);
    if (progfd == -1) {
        perror("prog load");
        puts(verifier_log);
        return 1;
    }
    puts("Program loaded");

    // make a socketpair and attach bpf program
    int socks[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
        err(1, "socketpair");
    if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
        err(1, "setsockopt");
    close(progfd);

    // trigger the program by writing to the socket
    if (write(socks[1], "a", 1) != 1)
        err(1, "write");
    puts("Program triggered");

    printf("Read from shared memory: x%x\n", array_get(map_fd, 1));

    // we can read what we wrote if the filter returned non-zero
    /* char c; */
    /* if (read(socks[0], &c, 1) != 1) */
    /*     err(1, "read res"); */
    return 0;
}
