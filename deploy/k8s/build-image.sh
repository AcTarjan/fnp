#!/bin/bash

docker build -t dpdk-slave:v1 .

#保存baseimage
#docker save baseimage:v1 > baseimage.tar