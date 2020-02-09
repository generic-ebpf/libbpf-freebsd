#pragma once

#include <stdint.h>

typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;

#define bpf_map_type ebpf_map_types
#define bpf_prog_type ebpf_prog_types
#define bpf_func_id ebpf_func_ids
#define bpf_insn ebpf_inst

enum bpf_attach_type {
	BPF_ATTACH_TYPE_NONE
};

struct bpf_prog_info {
	int _unused;
};
