#ifndef __ALMOND_CORE_FUZZER_COMMON_H__
#define __ALMOND_CORE_FUZZER_COMMON_H__

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/uio.h>

// Declared in libalmond.a (target.rs)
extern void fuzz(void* buffer, int syscall_no, int arg_no, int size);
extern void advance_offset(int syscall_no);

extern void libafl_main(void) __attribute__((weak));

#endif // __ALMOND_CORE_FUZZER_COMMON_H__
