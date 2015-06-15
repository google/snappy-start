#!/bin/bash

set -eu

g++ -O2 -Wall -Werror ptracer.cc -o ptracer
./ptracer /bin/echo "Hello world!"
