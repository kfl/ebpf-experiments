#define _GNU_SOURCE
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include "bpf_insn.h"


static long bpf_(int cmd, union bpf_attr *attrs) {
  return syscall(__NR_bpf, cmd, attrs, sizeof(*attrs));
}

static void array_set(int mapfd, uint32_t key, uint32_t value) {
  union bpf_attr attr = {
    .map_fd = mapfd,
    .key    = (uint64_t)&key,
    .value  = (uint64_t)&value,
    .flags  = BPF_ANY,
  };

  long res = bpf_(BPF_MAP_UPDATE_ELEM, &attr);
  if (res)
    err(1, "map update elem");
}

static uint32_t array_get(int map_fd, uint32_t key) {
  uint64_t ret_val;
  union bpf_attr lookup_map = {
    .map_fd = map_fd,
    .key    = (uint64_t)&key,
    .value  = (uint64_t)&ret_val
  };

  int res = bpf_(BPF_MAP_LOOKUP_ELEM, &lookup_map);
  if (res)
    err(1, "map lookup elem");
  return ret_val;
}

static uint32_t map_create() {
  union bpf_attr create_map_attrs = {
    .map_type    = BPF_MAP_TYPE_ARRAY,
    .key_size    = 4,
    .value_size  = 8,
    .max_entries = 16
  };

  uint32_t map_fd = bpf_(BPF_MAP_CREATE, &create_map_attrs);
  if (map_fd == -1)
    err(1, "map create");

  return map_fd;
}


int main(void) {

  uint32_t map_fd = map_create();

  int key = 1;
  int initial = 0xDEADBEEF;
  int value = 0x42424242;

  array_set(map_fd, key, initial);

  char verifier_log[100000];
  struct bpf_insn insns[] = {

      // The following code to shared memory using BPF_FUNC_map_update_elem,
      // which takes 4 parameters (R1: map_fd, R2: &key, R3: &value, R4: flags)

      // Load map into r1
      BPF_LD_MAP_FD(BPF_REG_1, map_fd),

      // Stack pointer in r2
      BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
      // Make room for it and write the key (32 bit)
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
      BPF_ST_MEM(BPF_W, BPF_REG_2, 0, key),

      // Make r3 a pointer to the value to write
      BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
      BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -16),

      // Put the value where r3 points to (via R4)
      BPF_MOV64_IMM(BPF_REG_4, value),
      BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_4, 0),

      // Set r4 == flags for update_elem
      BPF_MOV64_IMM(BPF_REG_4, BPF_ANY),

      // Call the bpf helper to update the map
      BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem),

      // Exit with 0
      BPF_MOV32_IMM(BPF_REG_0, 0), /* r0 = 0 */
      BPF_EXIT_INSN()};

  // load the program
  union bpf_attr create_prog_attrs = {
    .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
    .insn_cnt = sizeof(insns) / sizeof(insns[0]),
    .insns = (uint64_t)insns,
    .license = (uint64_t) "GPL",
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
  puts("Program loaded\n");

  // make a socketpair and attach bpf program
  int socks[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks))
    err(1, "socketpair");
  if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &progfd, sizeof(int)))
    err(1, "setsockopt");
  close(progfd);

  printf("Read from shared memory _before_ triggering\n"
         "     got: 0x%x\n"
         "expected: 0x%x\n\n",
         array_get(map_fd, key), initial);


  // trigger the program by writing to the socket
  if (write(socks[1], "a", 1) != 1)
    err(1, "write");

  puts("Program triggered\n");

  printf("Read from shared memory _after_ triggering\n"
         "     got: 0x%x\n"
         "expected: 0x%x\n",
         array_get(map_fd, key), value);

  // We can read what we wrote if the filter returned non-zero
  // However, if the filter returned zero the read will hang, thus it's commented out
  /* char c; */
  /* if (read(socks[0], &c, 1) != 1) */
  /*     err(1, "read res"); */
  return 0;
}
