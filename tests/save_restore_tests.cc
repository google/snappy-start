
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>


int main() {
  // Test munmap() of an entire mapping.
  int size = getpagesize();
  void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(addr != MAP_FAILED);
  int rc = munmap(addr, size);
  assert(rc == 0);

  // Test munmap() that splits up an existing mapping.
  void *addr2 = mmap(NULL, size * 3, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(addr2 != MAP_FAILED);
  ((char *) addr2)[0] = 'a';
  ((char *) addr2)[size * 2] = 'b';
  rc = munmap((char *) addr2 + size, size);
  assert(rc == 0);

  // Test mprotect() of an entire mapping.
  void *addr3 = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(addr3 != MAP_FAILED);
  *(int *) addr3 = 0x1234;
  rc = mprotect(addr3, size, PROT_READ);
  assert(rc == 0);

  // Test overwriting a mapping with MAP_FIXED.
  void *addr4 = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(addr4 != MAP_FAILED);
  void *result = mmap(addr4, size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
  assert(result == addr4);

  // Test that brk() is disabled before taking the snapshot.
  long break_ptr = syscall(__NR_brk, 0);
  assert(break_ptr == -1);
  assert(errno == ENOSYS);

  // Test malloc(), which we expect will try to use brk().
  int num_blocks = 100;
  char *blocks[num_blocks];
  for (int i = 0; i < num_blocks; ++i) {
    blocks[i] = (char *) malloc(100);
    assert(blocks[i]);
    *(int *) blocks[i] = i * 100;
  }

  raise(SIGUSR1);

  assert(((char *) addr2)[0] == 'a');
  assert(((char *) addr2)[size * 2] == 'b');

  assert(*(int *) addr3 == 0x1234);

  // Currently brk() works after resuming from the snapshot.
  long break_ptr_after = syscall(__NR_brk, 0);
  assert(break_ptr_after != -1);

  // Check that the malloc()'d blocks still work.
  for (int i = 0; i < num_blocks; ++i) {
    assert(*(int *) blocks[i] == i * 100);
  }

  return 0;
}
