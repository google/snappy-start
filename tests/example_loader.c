// Copyright 2015 Google Inc. All Rights Reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sys/mman.h>


static int my_errno;

#define SYS_ERRNO my_errno
#include "linux_syscall_support.h"


extern char code_start[], code_end[];
asm("code_start:\n"

    // Call getpid()
    "movl $39, %eax\n"
    "syscall\n"
    // Call kill(getpid(), SIGUSR1)
    "movl %eax, %edi\n" // arg1: result of getpid()
    "movl $10, %esi\n" // arg2: SIGUSR1
    "movl $62, %eax\n" // __NR_kill
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
