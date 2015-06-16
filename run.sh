#!/bin/bash

set -eu

cflags="-O2 -g -Wall -Werror"

gcc $cflags -static -nostdlib example_loader.c -o example_loader
./example_loader

g++ $cflags ptracer.cc -o ptracer
./ptracer ./example_loader
