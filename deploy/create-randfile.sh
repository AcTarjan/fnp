#!/bin/bash

count=1
if [ $# -gt 0 ]; then
    count=$1
fi

dd if=/dev/urandom bs=1KB count=$count | base64 > output/input.dat

