// Copyright 2015 Google Inc. All Rights Reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

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

uintptr_t RoundUpPageSize(uintptr_t val) {
  uintptr_t page_size = getpagesize();
  return (val + page_size - 1) & ~(page_size - 1);
}

class MmapInfo {
 public:
  uintptr_t addr;
  size_t size;
  // Current access permissions.
  int prot;
  // Maximum access permissions that this mapping has ever been
  // mmap()'d or mprotect()'d with.  This is used to determine whether
  // mapping could have been written to.
  int max_prot;
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

  void ChangeMapping(uintptr_t change_start, size_t change_size,
                     bool do_unmap, int new_prot) {
    change_size = RoundUpPageSize(change_size);
    uintptr_t change_end = change_start + change_size;
    assert(change_end >= change_start);
    for (std::list<MmapInfo>::iterator iter = mappings_.begin();
         iter != mappings_.end(); ) {
      std::list<MmapInfo>::iterator mapping = iter++;
      uintptr_t mapping_end = mapping->addr + mapping->size;
      // Does this existing mapping overlap with the range we are
      // unmapping?
      if (mapping_end <= change_start ||
          change_end <= mapping->addr) {
        // No overlap.
        continue;
      }
      // Do we need to keep the start and/or end of the existing
      // mapping?
      if (change_start > mapping->addr) {
        // Keep the start of the mapping.
        MmapInfo new_part(*mapping);
        new_part.size = change_start - mapping->addr;
        mappings_.insert(mapping, new_part);
      }
      if (change_end < mapping_end) {
        // Keep the end of the mapping.
        MmapInfo new_part(*mapping);
        size_t diff = change_end - mapping->addr;
        new_part.addr += diff;
        new_part.size -= diff;
        new_part.file_offset += diff;
        mappings_.insert(mapping, new_part);
      }
      if (do_unmap) {
        // munmap() case.
        mappings_.erase(mapping);
      } else {
        // mprotect() case.
        uintptr_t new_start = std::max(change_start, mapping->addr);
        uintptr_t new_end = std::min(change_end, mapping_end);
        mapping->file_offset += new_start - mapping->addr;
        mapping->addr = new_start;
        mapping->size = new_end - new_start;
        mapping->prot = new_prot;
        mapping->max_prot |= new_prot;
      }
    }
  }

  void HandleMunmap(uintptr_t addr, size_t size) {
    ChangeMapping(addr, size, true, 0);
  }

  void HandleMprotect(uintptr_t addr, size_t size, int prot) {
    ChangeMapping(addr, size, false, prot);
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

    if (syscall_result > -(uintptr_t) 0x1000) {
      // Syscall returned an error so should have had no effect.
      return;
    }

    switch (sysnum) {
      case __NR_open: {
        std::string filename(ReadString(arg1));
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
        uintptr_t addr = syscall_result;
        size_t size = RoundUpPageSize(arg2);
        assert(addr + size >= addr);
        // Record overwriting of any existing mappings in this range
        // in case this mmap() call uses MAP_FIXED.
        HandleMunmap(addr, size);

        MmapInfo map;
        map.addr = addr;
        map.size = size;
        map.prot = arg3;
        map.max_prot = map.prot;
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
        HandleMunmap(arg1, arg2);
        break;
      }
      case __NR_mprotect: {
        HandleMprotect(arg1, arg2, arg3);
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

      if (map.max_prot & PROT_WRITE) {
        Put(1);
        Put(mapfile_offset);
        for (uintptr_t offset = 0; offset < map.size;
             offset += sizeof(uintptr_t)) {
          uintptr_t word = ReadWord(map.addr + offset);
          fwrite(&word, sizeof(word), 1, mapfile);
        }
        mapfile_offset += map.size;
      } else {
        Put(0);
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
      struct user_regs_struct regs;
      rc = ptrace(PTRACE_GETREGS, pid, 0, &regs);
      assert(rc == 0);
      if (syscall_entry) {
        // Disable use of the brk() heap so that we don't have to save
        // and restore the brk() heap pointer and heap contents.
        if (regs.orig_rax == __NR_brk) {
          regs.orig_rax = -1;
          rc = ptrace(PTRACE_SETREGS, pid, 0, &regs);
          assert(rc == 0);
        }
      } else {
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
