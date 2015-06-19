
#include <assert.h>
#include <signal.h>
#include <sys/mman.h>
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

  raise(SIGUSR1);

  assert(((char *) addr2)[0] == 'a');
  assert(((char *) addr2)[size * 2] == 'b');

  return 0;
}
