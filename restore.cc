
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

struct RegsToRestore {
  uint64_t rax, rcx, rdx, rbx, rbp, rsi, rdi;
  uint64_t r8, r9, r10, r11, r12, r13, r14, r15;

  // Fields used by the instruction "iretq".  We use "ireq" to restore
  // rip and rsp at the same time.
  uint64_t rip;
  uint64_t cs;
  uint64_t flags;
  uint64_t rsp;
  uint64_t ss;
};

void RestoreRegs(struct RegsToRestore *regs) {
  asm("mov %%cs, %0" : "=r"(regs->cs));
  asm("mov %%ss, %0" : "=r"(regs->ss));

  asm("movq %0, %%rsp\n"
      "popq %%rax\n"
      "popq %%rcx\n"
      "popq %%rdx\n"
      "popq %%rbx\n"
      "popq %%rbp\n"
      "popq %%rsi\n"
      "popq %%rdi\n"
      "popq %%r8\n"
      "popq %%r9\n"
      "popq %%r10\n"
      "popq %%r11\n"
      "popq %%r12\n"
      "popq %%r13\n"
      "popq %%r14\n"
      "popq %%r15\n"
      "iretq\n"
      : : "r"(regs));
}

}

int main() {
  Reader reader("out_info");
  int mapfile_fd = open("out_pages", O_RDONLY);
  assert(mapfile_fd >= 0);

  RegsToRestore regs;
  regs.rax = reader.Get();
  regs.rcx = reader.Get();
  regs.rdx = reader.Get();
  regs.rbx = reader.Get();
  regs.rsp = reader.Get();
  regs.rbp = reader.Get();
  regs.rsi = reader.Get();
  regs.rdi = reader.Get();
  regs.r8 = reader.Get();
  regs.r9 = reader.Get();
  regs.r10 = reader.Get();
  regs.r11 = reader.Get();
  regs.r12 = reader.Get();
  regs.r13 = reader.Get();
  regs.r14 = reader.Get();
  regs.r15 = reader.Get();
  regs.rip = reader.Get();
  regs.flags = reader.Get();

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

  RestoreRegs(&regs);
  // Should not reach here.
  return 1;
}
