// Copyright 2015 Google Inc. All Rights Reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <signal.h>
#include <stdio.h>


int main(void) {
  raise(SIGUSR1);

  printf("In example_prog2.c!\n");
  return 0;
}
