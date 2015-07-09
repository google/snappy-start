// Copyright 2015 Google Inc. All Rights Reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/mman.h>


static int my_errno;

#define SYS_ERRNO my_errno
#include "linux_syscall_support.h"


extern char code_start[], code_end[];
asm("code_start:\n"

    // Do unhandled syscall -1 to trigger snapshotting
    "movq $-1, %rax\n"
    "syscall\n"

    // Call write()
    "movl $1, %edi\n" // arg 1: stdout
    "leaq string(%rip), %rsi\n" // arg 2: string
    "movl $string_end - string, %edx\n" // arg 3: length of string
    "movl $1, %eax\n" // __NR_write
    "syscall\n"

    // Call exit_group()
    "movl $0, %edi\n" // arg 1: stdout
    "movl $231, %eax\n" // __NR_exit_group
    "syscall\n"
    "hlt\n"

    "string:\n"
    ".ascii \"In example_loader.c!\\n\"\n"
    "string_end:\n"

    "code_end:\n");

static void my_memcpy(void *dest, const void *src, size_t size) {
  char *d = dest;
  const char *s = src;
  while (size > 0) {
    *d++ = *s++;
    size--;
  }
}

typedef void (*func_t)(void);

void _start() {
  size_t size = code_end - code_start;
  void *addr = sys_mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_ANON | MAP_PRIVATE, -1, 0);
  my_memcpy(addr, code_start, size);

  func_t func = (func_t) addr;
  func();
}
