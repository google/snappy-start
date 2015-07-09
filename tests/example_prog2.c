// Copyright 2015 Google Inc. All Rights Reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>


int main(void) {
  // Do unhandled syscall -1 to trigger snapshotting.
  int rc = syscall(-1);
  assert(rc == -1);
  assert(errno == ENOSYS);

  printf("In example_prog2.c!\n");
  return 0;
}
