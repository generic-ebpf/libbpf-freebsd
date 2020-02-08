/* SPDX-License-Identifier: BSD-2-Clause */

#include <string.h>

#include "libbpf_common.h"
#include "libbpf.h"

#define __printf(a, b)	__attribute__((format(printf, a, b)))

__printf(2, 3)
void libbpf_print(enum libbpf_print_level level, const char *format, ...)
{
	NOT_IMPLEMENTED;
}

void
bpf_program__unload(struct bpf_program *prog)
{
	NOT_IMPLEMENTED;
}

struct bpf_program *
bpf_object__find_program_by_title(const struct bpf_object *obj,
				  const char *title)
{
	NOT_IMPLEMENTED;
	return NULL;
}

struct bpf_program *
bpf_object__find_program_by_name(const struct bpf_object *obj,
				 const char *name)
{
	NOT_IMPLEMENTED;
	return NULL;
}

int
bpf_map__reuse_fd(struct bpf_map *map, int fd)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_map__resize(struct bpf_map *map, __u32 max_entries)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_program__load(struct bpf_program *prog, char *license, __u32 kern_ver)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_object__load_progs(struct bpf_object *obj, int log_level)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

struct bpf_object *
bpf_object__open_xattr(struct bpf_object_open_attr *attr)
{
	NOT_IMPLEMENTED;
	return NULL;
}

struct bpf_object *
bpf_object__open(const char *path)
{
	NOT_IMPLEMENTED;
	return NULL;
}

struct bpf_object *
bpf_object__open_file(const char *path, const struct bpf_object_open_opts *opts)
{
	NOT_IMPLEMENTED;
	return NULL;
}

struct bpf_object *
bpf_object__open_mem(const void *obj_buf, size_t obj_buf_sz,
		     const struct bpf_object_open_opts *opts)
{
	NOT_IMPLEMENTED;
	return NULL;
}

struct bpf_object *
bpf_object__open_buffer(const void *obj_buf, size_t obj_buf_sz,
			const char *name)
{
	NOT_IMPLEMENTED;
	return NULL;
}

int
bpf_object__unload(struct bpf_object *obj)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_object__load_xattr(struct bpf_object_load_attr *attr)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_object__load(struct bpf_object *obj)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

void
bpf_object__close(struct bpf_object *obj)
{
	NOT_IMPLEMENTED;
}

const char *
bpf_object__name(const struct bpf_object *obj)
{
	NOT_IMPLEMENTED;
	return NULL;
}

int
bpf_object__btf_fd(const struct bpf_object *obj)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_object__set_priv(struct bpf_object *obj, void *priv,
		bpf_object_clear_priv_t clear_priv)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

void *
bpf_object__priv(const struct bpf_object *obj)
{
	NOT_IMPLEMENTED;
	return NULL;
}

struct bpf_program *
bpf_program__next(struct bpf_program *prev, const struct bpf_object *obj)
{
	NOT_IMPLEMENTED;
	return NULL;
}

struct bpf_program *
bpf_program__prev(struct bpf_program *next, const struct bpf_object *obj)
{
	NOT_IMPLEMENTED;
	return NULL;
}

int
bpf_program__set_priv(struct bpf_program *prog, void *priv,
		bpf_program_clear_priv_t clear_priv)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

void *
bpf_program__priv(const struct bpf_program *prog)
{
	NOT_IMPLEMENTED;
	return NULL;
}

const char *
bpf_program__name(const struct bpf_program *prog)
{
	NOT_IMPLEMENTED;
	return NULL;
}

const char *
bpf_program__title(const struct bpf_program *prog, bool needs_copy)
{
	NOT_IMPLEMENTED;
	return NULL;
}

int
bpf_program__fd(const struct bpf_program *prog)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_program__set_prep(struct bpf_program *prog, int nr_instances,
		bpf_program_prep_t prep)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_program__nth_fd(const struct bpf_program *prog, int n)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

enum bpf_prog_type
bpf_program__get_type(struct bpf_program *prog)
{
	NOT_IMPLEMENTED;
	return 0;
}

enum bpf_attach_type
bpf_program__get_expected_attach_type(struct bpf_program *prog)
{
	NOT_IMPLEMENTED;
	return 0;
}

void
bpf_program__set_expected_attach_type(struct bpf_program *prog,
		enum bpf_attach_type type)
{
	NOT_IMPLEMENTED;
}

int
libbpf_prog_type_by_name(const char *name, enum bpf_prog_type *prog_type,
		enum bpf_attach_type *expected_attach_type)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
libbpf_find_vmlinux_btf_id(const char *name,
		enum bpf_attach_type attach_type)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
libbpf_attach_type_by_name(const char *name,
		enum bpf_attach_type *attach_type)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_map__fd(const struct bpf_map *map)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

const struct bpf_map_def *
bpf_map__def(const struct bpf_map *map)
{
	NOT_IMPLEMENTED;
	return NULL;
}

const char *
bpf_map__name(const struct bpf_map *map)
{
	NOT_IMPLEMENTED;
	return NULL;
}

__u32
bpf_map__btf_key_type_id(const struct bpf_map *map)
{
	NOT_IMPLEMENTED;
	return 0;
}

__u32
bpf_map__btf_value_type_id(const struct bpf_map *map)
{
	NOT_IMPLEMENTED;
	return 0;
}

int
bpf_map__set_priv(struct bpf_map *map, void *priv,
		bpf_map_clear_priv_t clear_priv)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

void *
bpf_map__priv(const struct bpf_map *map)
{
	NOT_IMPLEMENTED;
	return NULL;
}

bool
bpf_map__is_offload_neutral(const struct bpf_map *map)
{
	NOT_IMPLEMENTED;
	return false;
}

bool
bpf_map__is_internal(const struct bpf_map *map)
{
	NOT_IMPLEMENTED;
	return false;
}

void
bpf_map__set_ifindex(struct bpf_map *map, __u32 ifindex)
{
	NOT_IMPLEMENTED;
}

int
bpf_map__set_inner_map_fd(struct bpf_map *map, int fd)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

struct bpf_map *
bpf_map__next(const struct bpf_map *prev, const struct bpf_object *obj)
{
	NOT_IMPLEMENTED;
	return NULL;
}

struct bpf_map *
bpf_map__prev(const struct bpf_map *next, const struct bpf_object *obj)
{
	NOT_IMPLEMENTED;
	return NULL;
}

struct bpf_map *
bpf_object__find_map_by_name(const struct bpf_object *obj, const char *name)
{
	NOT_IMPLEMENTED;
	return NULL;
}

int
bpf_object__find_map_fd_by_name(const struct bpf_object *obj, const char *name)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

struct bpf_map *
bpf_object__find_map_by_offset(struct bpf_object *obj, size_t offset)
{
	NOT_IMPLEMENTED;
	return NULL;
}

long
libbpf_get_error(const void *ptr)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_prog_load(const char *file, enum bpf_prog_type type,
		struct bpf_object **pobj, int *prog_fd)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}

int
bpf_prog_load_xattr(const struct bpf_prog_load_attr *attr,
		struct bpf_object **pobj, int *prog_fd)
{
	NOT_IMPLEMENTED;
	return -ENOTSUP;
}
