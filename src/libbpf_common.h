#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>

#include "linux_glue.h"

#ifndef LIBBPF_API
#define LIBBPF_API __attribute__((visibility("default")))
#endif

#define NOT_IMPLEMENTED do { \
	static bool warned = false; \
	if (!warned) { \
		fprintf(stderr, "%s is not implemented\n", __func__); \
		warned = true; \
	} \
} while (0);
