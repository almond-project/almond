/*
 syz-compat.h - compatibility definitions for syzkaller executor
 Must be placed after all system headers to avoid unexpected static replacement.
*/

#ifndef __SYZ_COMPAT_H__
#define __SYZ_COMPAT_H__


#include "stdint.h"
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
#define bool int
#define true 1
#define false 0

static void failmsg(const char* err, const char* msg, ...)
{
	int e = errno;
	fprintf(stderr, "SYZFAIL: %s\n", err);
	if (msg) {
		va_list args;
		va_start(args, msg);
		vfprintf(stderr, msg, args);
		va_end(args);
	}
	fprintf(stderr, " (errno %d: %s)\n", e, strerror(e));
  abort();
}

static void fail(const char* err)
{
	failmsg(err, 0);
}

static void debug(const char* msg, ...)
{
	(void)msg;
	// int err = errno;
	// va_list args;
	// va_start(args, msg);
	// vfprintf(stderr, msg, args);
	// va_end(args);
	// fflush(stderr);
	// errno = err;
}

static void debug_dump_data(const char* data, int length)
{
	int i = 0;
	for (; i < length; i++) {
		debug("%02x ", data[i] & 0xff);
		if (i % 16 == 15)
			debug("\n");
	}
	if (i % 16 != 0)
		debug("\n");
}

#endif // __SYZ_COMPAT_H__
