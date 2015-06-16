
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>


namespace {

class Reader {
  char buf_[0x1000];
  size_t size_;
  size_t pos_;

 public:
  Reader(const char *filename): pos_(0) {
    int fd = open(filename, O_RDONLY);
    assert(fd >= 0);
    ssize_t got = read(fd, buf_, sizeof(buf_));
    assert(got >= 0);
    assert(got < (ssize_t) sizeof(buf_));
    size_ = got;
    int rc = close(fd);
    assert(rc == 0);
  }

  uint64_t Get() {
    assert(pos_ + sizeof(uint64_t) <= size_);
    uint64_t val;
    memcpy(&val, &buf_[pos_], sizeof(val));
    pos_ += sizeof(uint64_t);
    return val;
  }

  const char *GetString() {
    size_t len = Get();
    const char *str = &buf_[pos_];
    pos_ += len + 1;
    assert(pos_ <= size_);
    return str;
  }
};

}

int main() {
  Reader reader("out_info");
  int mapfile_fd = open("out_pages", O_RDONLY);
  assert(mapfile_fd >= 0);

  uintptr_t rip = reader.Get();

  int mapping_count = reader.Get();
  for (int i = 0; i < mapping_count; i++) {
    void *addr = (void *) reader.Get();
    uintptr_t size = reader.Get();
    uintptr_t prot = reader.Get();
    const char *filename = reader.GetString();
    uintptr_t file_offset = reader.Get();

    if (prot & PROT_WRITE) {
      uintptr_t mapfile_offset = reader.Get();
      void *addr2 = mmap(addr, size, prot, MAP_PRIVATE | MAP_FIXED,
                         mapfile_fd, mapfile_offset);
      assert(addr2 == addr);
    } else {
      assert(*filename);
      int fd = open(filename, O_RDONLY);
      assert(fd >= 0);

      void *addr2 = mmap(addr, size, prot, MAP_PRIVATE | MAP_FIXED,
                         fd, file_offset);
      assert(addr2 == addr);

      int rc = close(fd);
      assert(rc == 0);
    }
  }

  int rc = close(mapfile_fd);
  assert(rc == 0);

  void (*func)() = (void (*)()) rip;
  func();
  // Should not return.
  abort();
}
