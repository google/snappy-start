
#include <assert.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>


int main() {
  // Test munmap().
  int size = getpagesize();
  void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANON, -1, 0);
  assert(addr != NULL);
  int rc = munmap(addr, size);
  assert(rc == 0);

  raise(SIGUSR1);

  return 0;
}
