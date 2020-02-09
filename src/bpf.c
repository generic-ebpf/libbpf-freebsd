#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "bpf.h"

static int
ebpf_ioctl(int cmd, void *req)
{
	int fd, error;

	fd = open("/dev/ebpf", O_RDWR);
	if (fd == -1) {
		return -errno;
	}

	error = ioctl(fd, cmd, req);
	if (error == -1) {
		error = -errno;
		goto end;
	}

end:
	close(fd);
	return error;
}

int
bpf_btf_get_fd_by_id(uint32_t id)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_create_map_xattr(const struct bpf_create_map_attr *create_attr)
{
	int fd, error;
	struct ebpf_map_create_req req = {};

	req.env = EBPF_ENV_KERNEL;
	req.type = create_attr->map_type;
	req.key_size = create_attr->key_size;
	req.value_size = create_attr->value_size;
	req.max_entries = create_attr->max_entries;
	req.flags = create_attr->map_flags;
	req.fdp = &fd;

	error = ebpf_ioctl(EBPFIOC_MAP_CREATE, &req);
	if (error == -1) {
		return -errno;
	}

	return (int)(*req.fdp);
}

int
bpf_create_map(enum bpf_map_type map_type, int key_size,
		int value_size, int max_entries, __u32 map_flags)
{
	int fd, error;
	struct ebpf_map_create_req req = {};

	req.type = map_type;
	req.key_size = key_size;
	req.value_size = value_size;
	req.max_entries = max_entries;
	req.flags = map_flags;
	req.fdp = &fd;

	error = ebpf_ioctl(EBPFIOC_MAP_CREATE, &req);
	if (error == -1) {
		return -errno;
	}

	return (int)(*req.fdp);
}

int
bpf_create_map_in_map(enum bpf_map_type map_type, const char *name,
		int key_size, int inner_map_fd, int max_entries,
		__u32 map_flags)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_create_map_in_map_node(enum bpf_map_type map_type, const char *name,
		int key_size, int inner_map_fd, int max_entries,
		__u32 map_flags, int node)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_create_map_name(enum bpf_map_type map_type, const char *name,
			int key_size, int value_size, int max_entries,
			__u32 map_flags)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_create_map_node(enum bpf_map_type map_type, const char *name,
		int key_size, int value_size, int max_entries,
		__u32 map_flags, int node)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_load_btf(void *btf, __u32 btf_size, char *log_buf, __u32 log_buf_size,
		bool do_log)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_load_program_xattr(const struct bpf_load_program_attr *load_attr,
		char *log_buf, size_t log_buf_sz)
{
	int fd, error;
	struct ebpf_load_prog_req req;

	if (load_attr == NULL || log_buf == NULL || log_buf_sz == 0) {
		return -EINVAL;
	}

	req.env = EBPF_ENV_KERNEL;
	req.type = load_attr->prog_type;
	req.prog_len = load_attr->insns_cnt;
	req.prog = (void *)load_attr->insns;
	req.fdp = &fd;

	error = ebpf_ioctl(EBPFIOC_LOAD_PROG, &req);
	if (error) {
		return -errno;
	}

	return (int)(*req.fdp);
}

int
bpf_load_program(enum bpf_prog_type type, const struct bpf_insn *insns,
		size_t insns_cnt, const char *license,
		__u32 kern_version, char *log_buf,
		size_t log_buf_sz)
{
	struct bpf_load_program_attr load_attr = {};

	load_attr.prog_type = type;
	load_attr.expected_attach_type = 0;
	load_attr.name = NULL;
	load_attr.insns = insns;
	load_attr.insns_cnt = insns_cnt;
	load_attr.license = license;
	load_attr.kern_version = kern_version;

	return bpf_load_program_xattr(&load_attr, log_buf, log_buf_sz);
}

int
bpf_map_delete_elem(int fd, const void *key)
{
	struct ebpf_map_delete_req req = {};

	req.fd = fd;
	req.key = (void *)key;

	return ebpf_ioctl(EBPFIOC_MAP_DELETE_ELEM, &req);
}

int
bpf_map_get_fd_by_id(__u32 id)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_map_get_next_id(__u32 start_id, __u32 *next_id)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
	struct ebpf_map_get_next_key_req req;

	req.fd = fd;
	req.key = (void *)key;
	req.next_key = next_key;

	return ebpf_ioctl(EBPFIOC_MAP_GET_NEXT_KEY, &req);
}

int
bpf_map_lookup_and_delete_elem(int fd, const void *key, void *value)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	struct ebpf_map_lookup_req req;

	req.fd = fd;
	req.key = (void *)key;
	req.value = value;

	return ebpf_ioctl(EBPFIOC_MAP_LOOKUP_ELEM, &req);
}

int
bpf_map_update_elem(int fd, const void *key, const void *value,
		__u64 flags)
{
	struct ebpf_map_update_req req;

	req.fd = fd;
	req.key = (void *)key;
	req.value = (void *)value;

	return ebpf_ioctl(EBPFIOC_MAP_UPDATE_ELEM, &req);
}

int
bpf_obj_get(const char *pathname)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_obj_get_info_by_fd(int prog_fd, void *info, __u32 *info_len)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_obj_pin(int fd, const char *pathname)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_prog_attach(int prog_fd, int target_fd, enum bpf_attach_type type,
		unsigned int flags)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_prog_detach(int target_fd, enum bpf_attach_type type)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_prog_detach2(int prog_fd, int target_fd, enum bpf_attach_type type)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_prog_get_fd_by_id(__u32 id)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_prog_get_next_id(__u32 start_id, __u32 *next_id)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_prog_query(int target_fd, enum bpf_attach_type type, __u32 query_flags,
		__u32 *attach_flags, __u32 *prog_ids, __u32 *prog_cnt)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_prog_test_run(int prog_fd, int repeat, void *data, __u32 size,
		void *data_out, __u32 *size_out, __u32 *retval,
		__u32 *duration)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_prog_test_run_xattr(struct bpf_prog_test_run_attr *test_attr)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_raw_tracepoint_open(const char *name, int prog_fd)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_task_fd_query(int pid, int fd, __u32 flags, char *buf, __u32 *buf_len,
		__u32 *prog_id, __u32 *fd_type, __u64 *probe_offset,
		__u64 *probe_addr)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_verify_program(enum bpf_prog_type type, const struct bpf_insn *insns,
		size_t insns_cnt, __u32 prog_flags, const char *license,
		__u32 kern_version, char *log_buf, size_t log_buf_sz,
		int log_level)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_map_lookup_elem_flags(int fd, const void *key, void *value, __u64 flags)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}
