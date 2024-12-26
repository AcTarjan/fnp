#!/bin/bash

cat output/input.dat | nc -s 192.168.11.16 192.168.11.22 18888 > output/nc.dat
