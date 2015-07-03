#!/bin/bash
# Copyright 2015 Google Inc. All Rights Reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -eu

cflags="-I. -O2 -g -Wall -Werror -Wundef"

mkdir -p out

gcc $cflags -static -nostdlib tests/example_loader.c -o out/example_loader
gcc $cflags -static -nostdlib tests/example_prog.c -o out/example_prog
gcc $cflags tests/example_prog2.c -o out/example_prog2
g++ $cflags -std=c++11 ptracer.cc -o out/ptracer

g++ $cflags -std=c++11 -fno-stack-protector -c restore.cc -o out/restore.o
ld.bfd -m elf_x86_64 --build-id -static -z max-page-size=0x1000 \
    --defsym RESERVE_TOP=0 --script elf_loader_linker_script.x \
    out/restore.o -o out/restore

gcc $cflags -fno-stack-protector -c elf_loader.c -o out/elf_loader.o
ld.bfd -m elf_x86_64 --build-id -static -z max-page-size=0x1000 \
    --defsym RESERVE_TOP=0 --script elf_loader_linker_script.x \
    out/elf_loader.o -o out/elf_loader

gcc $cflags tests/hellow.c -o out/hellow_exec
gcc $cflags tests/hellow.c -fPIE -pie -o out/hellow_pie

gcc $cflags tests/save_restore_tests.cc -o out/save_restore_tests


# Run tests

./out/elf_loader ./out/hellow_pie
./out/elf_loader ./out/hellow_exec

python tests/run_tests.py
