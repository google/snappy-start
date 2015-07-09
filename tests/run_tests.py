# Copyright 2015 Google Inc. All Rights Reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import struct
import subprocess


__NR_getpid = 39
__NR_mknod = 133


def AssertEquals(x, y):
  if x != y:
    raise AssertionError('%r != %r' % (x, y))


def GetSnapshotSyscallNumber():
  fh = open('out_info', 'r')
  rax = struct.unpack('q', fh.read(8))[0]
  return rax


def RunTest(cmd, sysnum, use_elf_loader=True):
  if use_elf_loader:
    cmd = ['./out/elf_loader'] + cmd
  print '* Running test: %s' % ' '.join(cmd)
  subprocess.check_call(['./out/ptracer'] + cmd)
  # Check that the program was snapshotted at the expected syscall.
  # Otherwise, it could have been stopped earlier than we expected,
  # which would mean we wouldn't be testing the parts we expected to
  # test.
  AssertEquals(GetSnapshotSyscallNumber(), sysnum)
  subprocess.check_call(['./out/restore'])


def Main():
  # This is a bare-bones test that does not need to be run through
  # elf_loader in order to be restored.
  RunTest(['./out/example_loader'], -1, use_elf_loader=False)

  RunTest(['./out/example_prog'], __NR_getpid)
  RunTest(['./out/example_prog2'], -1)

  # Get list of sub-test names.
  proc = subprocess.Popen(['./out/save_restore_tests'], stdout=subprocess.PIPE)
  stdout = proc.communicate()[0]
  test_names = stdout.strip().split('\n')

  for test_name in test_names:
    RunTest(['./out/save_restore_tests', test_name], -1)

  RunTest(['/usr/bin/python', 'tests/python_example.py'], __NR_mknod)


if __name__ == '__main__':
  Main()
