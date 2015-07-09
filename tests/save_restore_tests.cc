// Copyright 2015 Google Inc. All Rights Reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>


namespace {

void do_snapshot() {
  // Do unhandled syscall -1 to trigger snapshotting.
  int rc = syscall(-1);
  assert(rc == -1);
  assert(errno == ENOSYS);
}

void test_munmap_whole_mapping() {
  // Test munmap() of an entire mapping.
  int size = getpagesize();
  void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(addr != MAP_FAILED);
  int rc = munmap(addr, size);
  assert(rc == 0);

  do_snapshot();
}

void test_munmap_splits_mapping() {
  // Test munmap() that splits up an existing mapping.
  int size = getpagesize();
  void *addr2 = mmap(NULL, size * 3, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(addr2 != MAP_FAILED);
  ((char *) addr2)[0] = 'a';
  ((char *) addr2)[size * 2] = 'b';
  int rc = munmap((char *) addr2 + size, size);
  assert(rc == 0);

  do_snapshot();

  assert(((char *) addr2)[0] == 'a');
  assert(((char *) addr2)[size * 2] == 'b');
}

void test_mprotect() {
  // Test mprotect() of an entire mapping.
  int size = getpagesize();
  void *addr3 = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(addr3 != MAP_FAILED);
  *(int *) addr3 = 0x1234;
  int rc = mprotect(addr3, size, PROT_READ);
  assert(rc == 0);

  do_snapshot();

  assert(*(int *) addr3 == 0x1234);
}

void test_mmap_fixed_overwrites() {
  // Test overwriting a mapping with MAP_FIXED.
  int size = getpagesize();
  void *addr4 = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(addr4 != MAP_FAILED);
  void *result = mmap(addr4, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
  assert(result == addr4);

  do_snapshot();
}

void check_addr_is_reserved(void *addr) {
  void *mapping = mmap(addr, getpagesize(), PROT_NONE,
                       MAP_PRIVATE | MAP_ANON, -1, 0);
  // |addr| should already be taken, so the kernel should have picked
  // a different address.
  assert(mapping != addr);
  // Clean up.
  int rc = munmap(mapping, getpagesize());
  assert(rc == 0);
}

void test_mmap_prot_none() {
  // Test restoring a PROT_NONE page that was never writable.
  void *addr = mmap(NULL, getpagesize(), PROT_NONE,
                    MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(addr != MAP_FAILED);

  do_snapshot();

  check_addr_is_reserved(addr);
}

void test_many_mappings() {
  // Test that we can handle a large number of mappings.
  int page_size = getpagesize();
  int pages = 100;
  uintptr_t addr =
    (uintptr_t) mmap(NULL, pages * page_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(addr != (uintptr_t) MAP_FAILED);

  // Change every other page.
  for (int i = 0; i < pages; i += 2) {
    int rc = mprotect((void *) (addr + i * page_size), page_size, PROT_READ);
    assert(rc == 0);
  }

  do_snapshot();
}

void test_brk() {
  // Test that brk() is disabled before taking the snapshot.
  long break_ptr = syscall(__NR_brk, 0);
  assert(break_ptr == -1);
  assert(errno == ENOSYS);

  do_snapshot();

  // Currently brk() works after resuming from the snapshot.
  long break_ptr_after = syscall(__NR_brk, 0);
  assert(break_ptr_after != -1);
}

void test_malloc() {
  // Test malloc(), which we expect will try to use brk().
  int num_blocks = 100;
  char *blocks[num_blocks];
  for (int i = 0; i < num_blocks; ++i) {
    blocks[i] = (char *) malloc(100);
    assert(blocks[i]);
    *(int *) blocks[i] = i * 100;
  }

  do_snapshot();

  // Check that the malloc()'d blocks still work.
  for (int i = 0; i < num_blocks; ++i) {
    assert(*(int *) blocks[i] == i * 100);
  }
}

void test_vdso_removed_from_auxv() {
  // Test that the auxv's pointers to the VDSO have been removed.
  char **envp_end = environ;
  while (*envp_end)
    envp_end++;
  Elf64_auxv_t *auxv = (Elf64_auxv_t *) (envp_end + 1);
  for (; auxv->a_type != AT_NULL; ++auxv) {
    assert(auxv->a_type != AT_SYSINFO);
    assert(auxv->a_type != AT_SYSINFO_EHDR);
  }

  do_snapshot();
}

void test_gettimeofday() {
  do_snapshot();

  // Test gettimeofday(), which we expect will try to use the VDSO.
  struct timeval time;
  int rc = gettimeofday(&time, NULL);
  assert(rc == 0);
}

struct TestCase {
  const char *test_name;
  void (*test_func)();
};

const TestCase test_cases[] = {
#define TEST_CASE(NAME) { #NAME, NAME }
  TEST_CASE(test_munmap_whole_mapping),
  TEST_CASE(test_munmap_splits_mapping),
  TEST_CASE(test_mprotect),
  TEST_CASE(test_mmap_fixed_overwrites),
  TEST_CASE(test_mmap_prot_none),
  TEST_CASE(test_many_mappings),
  TEST_CASE(test_brk),
  TEST_CASE(test_malloc),
  TEST_CASE(test_vdso_removed_from_auxv),
  TEST_CASE(test_gettimeofday),
#undef TEST_CASE
};

}

int main(int argc, char **argv) {
  size_t test_count = sizeof(test_cases) / sizeof(test_cases[0]);

  if (argc == 1) {
    // Print list of test cases.
    for (size_t i = 0; i < test_count; ++i) {
      printf("%s\n", test_cases[i].test_name);
    }
    return 0;
  }

  if (argc == 2) {
    // Run one test case.
    const char *test_name = argv[1];
    for (size_t i = 0; i < test_count; ++i) {
      if (strcmp(test_cases[i].test_name, test_name) == 0) {
        test_cases[i].test_func();
        return 0;
      }
    }
    printf("Test case not found: %s\n", test_name);
    return 1;
  }

  printf("Usage: %s [test_name]\n", argv[0]);
  return 1;
}
