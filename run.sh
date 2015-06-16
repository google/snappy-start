#!/bin/bash

set -eu

cflags="-O2 -g -Wall -Werror -Wundef"

gcc $cflags -static -nostdlib example_loader.c -o example_loader
gcc $cflags -static -nostdlib example_prog.c -o example_prog
gcc $cflags example_prog2.c -o example_prog2
g++ $cflags -std=c++11 ptracer.cc -o ptracer
g++ $cflags -std=c++11 -Wl,-Ttext-segment=0x1000000 restore.cc -o restore

gcc $cflags -fno-stack-protector -c elf_loader.c
ld.bfd -m elf_x86_64 --build-id -static -z max-page-size=0x1000 \
    --defsym RESERVE_TOP=0 --script elf_loader_linker_script.x \
    elf_loader.o -o elf_loader

gcc $cflags hellow.c -o hellow_exec
gcc $cflags hellow.c -fPIE -pie -o hellow_pie

./elf_loader ./hellow_pie
./elf_loader ./hellow_exec

./ptracer ./example_loader
./restore

./ptracer ./elf_loader ./example_prog
./restore

./ptracer ./elf_loader ./example_prog2
./restore
