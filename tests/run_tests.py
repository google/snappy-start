# Copyright 2015 Google Inc. All Rights Reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import subprocess


def RunTest(cmd, use_elf_loader=True):
  if use_elf_loader:
    cmd = ['./out/elf_loader'] + cmd
  print '* Running test: %s' % ' '.join(cmd)
  subprocess.check_call(['./out/ptracer'] + cmd)
  subprocess.check_call(['./out/restore'])


def Main():
  # This is a bare-bones test that does not need to be run through
  # elf_loader in order to be restored.
  RunTest(['./out/example_loader'], use_elf_loader=False)

  RunTest(['./out/example_prog'])
  RunTest(['./out/example_prog2'])

  # Get list of sub-test names.
  proc = subprocess.Popen(['./out/save_restore_tests'], stdout=subprocess.PIPE)
  stdout = proc.communicate()[0]
  test_names = stdout.strip().split('\n')

  for test_name in test_names:
    RunTest(['./out/save_restore_tests', test_name])

  RunTest(['/usr/bin/python', 'tests/python_example.py'])


if __name__ == '__main__':
  Main()
