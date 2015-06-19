
#include <asm/prctl.h>
#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <list>
#include <map>
#include <sstream>


// This is an example of using ptrace() to log syscalls called by a
// child process.

namespace {

// Flag which is set in the signal number for syscall entry/exit when
// the option PTRACE_O_TRACESYSGOOD is enabled.
const int kSysFlag = 0x80;

const char *SyscallName(int sysnum) {
  switch (sysnum) {
#define MAP(name) case __NR_##name: return #name;
    MAP(access)
    MAP(arch_prctl)
    MAP(brk)
    MAP(close)
    MAP(execve)
    MAP(exit)
    MAP(exit_group)
    MAP(fstat)
    MAP(mmap)
    MAP(mprotect)
    MAP(munmap)
    MAP(open)
    MAP(read)
    MAP(write)
    default: return "?";
  }
}

uintptr_t RoundUpPageSize(uintptr_t val) {
  uintptr_t page_size = getpagesize();
  return (val + page_size - 1) & ~(page_size - 1);
}

class MmapInfo {
 public:
  uintptr_t addr;
  size_t size;
  int prot;
  std::string filename;
  uint64_t file_offset;
};

class Ptracer {
  int pid_;
  std::list<MmapInfo> mappings_;
  std::map<int, std::string> fds_;
  uint64_t fs_segment_base_;
  FILE *info_fp_;

  uintptr_t ReadWord(uintptr_t addr) {
    errno = 0;
    uintptr_t value = ptrace(PTRACE_PEEKDATA, pid_, addr, 0);
    assert(errno == 0);
    return value;
  }

  char ReadByte(uintptr_t addr) {
    uintptr_t mask = sizeof(uintptr_t) - 1;
    uintptr_t word = ReadWord(addr & ~mask);
    return word >> ((addr & mask) * 8);
  }

  std::string ReadString(uintptr_t addr) {
    // TODO: Reading one byte at a time is inefficient (though reading
    // one word at a time is not great either).
    std::stringbuf buf;
    for (;;) {
      char ch = ReadByte(addr++);
      if (!ch)
        break;
      buf.sputc(ch);
    }
    return buf.str();
  }

 public:
  Ptracer(int pid): pid_(pid) {}

  void HandleSyscall(struct user_regs_struct *regs) {
    uintptr_t sysnum = regs->orig_rax;
    uintptr_t syscall_result = regs->rax;
    uintptr_t arg1 = regs->rdi;
    uintptr_t arg2 = regs->rsi;
    uintptr_t arg3 = regs->rdx;
    // uintptr_t arg4 = regs->r10;
    uintptr_t arg5 = regs->r8;
    uintptr_t arg6 = regs->r9;
    printf("syscall=%s (%i)\n", SyscallName(sysnum), (int) sysnum);

    if (syscall_result > -(uintptr_t) 0x1000) {
      // Syscall returned an error so should have had no effect.
      return;
    }

    switch (sysnum) {
      case __NR_open: {
        std::string filename(ReadString(arg1));
        printf("open: %s\n", filename.c_str());
        int fd_result = syscall_result;
        if (fd_result >= 0)
          fds_[fd_result] = filename;
        break;
      }
      case __NR_close: {
        fds_.erase(arg1);
        break;
      }
      case __NR_mmap: {
        MmapInfo map;
        map.addr = syscall_result;
        map.size = RoundUpPageSize(arg2);
        assert(map.addr + map.size >= map.addr);
        map.prot = arg3;
        // assert(arg4 == (MAP_ANON | MAP_PRIVATE));
        int fd_arg = arg5;
        if (fd_arg != -1) {
          assert(fds_.find(fd_arg) != fds_.end());
          map.filename = fds_[fd_arg];
        }
        map.file_offset = arg6;
        mappings_.push_back(map);
        break;
      }
      case __NR_munmap: {
        uintptr_t unmap_start = arg1;
        uintptr_t unmap_size = RoundUpPageSize(arg2);
        uintptr_t unmap_end = unmap_start + unmap_size;
        assert(unmap_end >= unmap_start);
        for (std::list<MmapInfo>::iterator iter = mappings_.begin();
             iter != mappings_.end(); ) {
          std::list<MmapInfo>::iterator mapping = iter++;
          uintptr_t mapping_end = mapping->addr + mapping->size;
          // Does this existing mapping overlap with the range we are
          // unmapping?
          if (mapping_end <= unmap_start ||
              unmap_end <= mapping->addr) {
            // No overlap.
            continue;
          }
          // Do we need to keep the start and/or end of the existing
          // mapping?
          if (unmap_start > mapping->addr) {
            // Keep the start of the mapping.
            MmapInfo new_part(*mapping);
            new_part.size = unmap_start - mapping->addr;
            mappings_.insert(mapping, new_part);
          }
          if (unmap_end < mapping_end) {
            // Keep the end of the mapping.
            MmapInfo new_part(*mapping);
            size_t diff = unmap_end - mapping->addr;
            new_part.addr += diff;
            new_part.size -= diff;
            new_part.file_offset += diff;
            mappings_.insert(mapping, new_part);
          }
          mappings_.erase(mapping);
        }
        break;
      }
      case __NR_arch_prctl: {
        if (arg1 == ARCH_SET_FS) {
          fs_segment_base_ = arg2;
        }
        break;
      }
    }
  }

  void Put(uint64_t val) {
    fwrite(&val, sizeof(val), 1, info_fp_);
  }

  void PutString(const std::string &str) {
    Put(str.size());
    fwrite(str.c_str(), str.size() + 1, 1, info_fp_);
  }

  void Dump() {
    // We don't support restoring FDs yet, so no FDs must be left open.
    assert(fds_.size() == 0);

    FILE *mapfile = fopen("out_pages", "w");
    assert(mapfile);
    uintptr_t mapfile_offset = 0;

    info_fp_ = fopen("out_info", "w");
    assert(info_fp_);

    struct user_regs_struct regs;
    int rc = ptrace(PTRACE_GETREGS, pid_, 0, &regs);
    assert(rc == 0);
    Put(regs.rax);
    Put(regs.rcx);
    Put(regs.rdx);
    Put(regs.rbx);
    Put(regs.rsp);
    Put(regs.rbp);
    Put(regs.rsi);
    Put(regs.rdi);
    Put(regs.r8);
    Put(regs.r9);
    Put(regs.r10);
    Put(regs.r11);
    Put(regs.r12);
    Put(regs.r13);
    Put(regs.r14);
    Put(regs.r15);
    Put(regs.rip);
    Put(regs.eflags);
    Put(fs_segment_base_);

    Put(mappings_.size());
    for (auto &map : mappings_) {
      Put(map.addr);
      Put(map.size);
      Put(map.prot);
      PutString(map.filename);
      Put(map.file_offset);

      if (map.prot & PROT_WRITE) {
        Put(mapfile_offset);
        for (uintptr_t offset = 0; offset < map.size;
             offset += sizeof(uintptr_t)) {
          uintptr_t word = ReadWord(map.addr + offset);
          fwrite(&word, sizeof(word), 1, mapfile);
        }
        mapfile_offset += map.size;
      }
    }
    fclose(mapfile);
    fclose(info_fp_);
  }

  void TerminateSubprocess() {
    int rc = kill(pid_, SIGKILL);
    assert(rc == 0);

    // Wait for the SIGKILL signal to take effect.
    int status;
    int pid2 = waitpid(pid_, &status, 0);
    assert(pid2 == pid_);
    assert(WIFSIGNALED(status));
    assert(WTERMSIG(status) == SIGKILL);
  }
};

}

int main(int argc, char **argv) {
  assert(argc >= 2);

  int pid = fork();
  assert(pid >= 0);
  if (pid == 0) {
    // Start tracing of the current process by the parent process.
    int rc = ptrace(PTRACE_TRACEME);
    assert(rc == 0);

    // This will trigger a SIGTRAP signal, which the parent will catch.
    execv(argv[1], argv + 1);
    perror("exec");

    _exit(1);
  }

  // Wait for the initial SIGTRAP signal generated by the child's
  // execve() call.  Since we haven't done PTRACE_SETOPTIONS yet,
  // kSysFlag isn't set in the signal number yet.
  int status;
  int pid2 = waitpid(pid, &status, 0);
  assert(pid2 == pid);
  assert(WIFSTOPPED(status));
  assert(WSTOPSIG(status) == SIGTRAP);

  // Enable kSysFlag.
  int rc = ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
  assert(rc == 0);

  // Allow the process to continue until the next syscall entry/exit.
  rc = ptrace(PTRACE_SYSCALL, pid, 0, 0);
  assert(rc == 0);

  // Whether the next signal will indicate a syscall entry.  If false,
  // the next signal will indicate a syscall exit.
  bool syscall_entry = true;

  Ptracer ptracer(pid);
  for (;;) {
    int status;
    int rc = waitpid(pid, &status, 0);
    assert(rc == pid);

    assert(WIFSTOPPED(status));

    if (WSTOPSIG(status) == (SIGTRAP | kSysFlag)) {
      if (!syscall_entry) {
        struct user_regs_struct regs;
        rc = ptrace(PTRACE_GETREGS, pid, 0, &regs);
        assert(rc == 0);
        ptracer.HandleSyscall(&regs);
      }
      syscall_entry = !syscall_entry;

      // Allow the process to continue until the next syscall entry/exit.
      rc = ptrace(PTRACE_SYSCALL, pid, 0, 0);
      assert(rc == 0);
    } else if (WSTOPSIG(status) == SIGUSR1) {
      ptracer.Dump();
      ptracer.TerminateSubprocess();
      break;
    }
  }
  return 0;
}
